//! `swarm-manifest-grants.json` (the reference's
//! `swarm/permission-manifests.js`): each site's permission-manifest
//! decisions, the grants a manifest manages for it, and its receipts.
//!
//! `{ version: 1, records: { [key]: { managed, acknowledged, detached?,
//! observed, app, revision, receipts? } }, pending? }`. `managed` names, for
//! each projection a manifest turned on (the connection, the identity, the
//! feed grant, the messaging grant, an auto-approve flag), the capabilities
//! that own it; `pending` is a change's journal.
//!
//! Every change is the reference's transaction ([`World`]): the journal
//! written first (`pending`), then each projection applied to the Swarm
//! grants (0012) or the feed store, then the record committed and the
//! journal cleared. A journal left by a crash or a failed step is replayed
//! before the next change ([`ManifestStore::recover_pending`]). Each write
//! copies the file as it stands to `.bak` first ([`Save::backup`]), unless
//! the store was read from that backup.
//!
//! The manifest itself is main's to fetch ([`ManifestStore::check`] answers
//! [`CheckStep::Fetch`] where the reference fetches, with the address), and
//! the core's to read: at most [`MAX_MANIFEST_BYTES`], UTF-8, JSON, and
//! `validateManifest`'s schema. The consent tokens and the unresolved
//! backoff live in memory, as the reference's do.
//!
//! What differs from the reference:
//! - The bound (design 0015, Budgets): a write whose text would pass
//!   [`MAX_FILE_BYTES`] is refused (`store_full`), and the store reads its
//!   file again, as after a failed write.
//! - A file the reference reads but can't use is read as one that doesn't
//!   parse (the backup, else [`Unreadable`]: deviation `store-shapes`,
//!   `manifest-load-record-shape` and `manifest-load-string-revision`),
//!   and no reference writer makes one: past [`MAX_FILE_BYTES`];
//!   not an object; `records` not an object of records; a record whose
//!   `managed` isn't an object of arrays under known projections, whose
//!   `acknowledged` isn't an object under known capabilities, whose
//!   `detached` isn't an object, whose `revision` isn't a number or whose
//!   `receipts` isn't an array (the reference throws on these, or
//!   concatenates a string revision); a journal that isn't `{ origin,
//!   record, operations }` of a string, a record or `null`, and known
//!   projections with boolean `enabled`.

use fc_json::{JsString, JsValue};
use sha2::{Digest, Sha256};

use super::feeds::FeedStore;
use super::origin::normalize_origin;
use super::{
    Thrown, UNDEFINED, get, get_mut, is_plain_object, object, parse_file, props, remove, spread,
    text, time, truthy,
};

/// The file's name at the Freedom root.
pub const FILE_NAME: &str = "swarm-manifest-grants.json";

/// Its backup's name, beside it.
pub const BACKUP_NAME: &str = "swarm-manifest-grants.json.bak";

/// The most the file may hold, in bytes (design 0015, Budgets: 1 MiB).
pub const MAX_FILE_BYTES: usize = 1024 * 1024;

/// The most a manifest may hold, in bytes (`MAX_BYTES`, 8 KiB).
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024;

/// `TOKEN_TTL_MS`.
const TOKEN_TTL_MS: u64 = 5 * 60 * 1000;
/// `MAX_PAGE_TOKENS`.
pub const MAX_PAGE_TOKENS: usize = 64;
/// `MAX_RECEIPTS`.
const MAX_RECEIPTS: usize = 20;
/// The decided in-process consents kept for a replay.
const MAX_COMPLETED: usize = 100;
/// `UNRESOLVED_BACKOFF_MS`.
const UNRESOLVED_BACKOFF_MS: [u64; 4] = [2_000, 10_000, 30_000, 60_000];

/// A manifest's capability (`CAPABILITY_KEYS`, in that order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    Publish,
    Feeds,
    Signing,
    Messaging,
}

impl Capability {
    pub const ALL: [Capability; 4] = [
        Capability::Publish,
        Capability::Feeds,
        Capability::Signing,
        Capability::Messaging,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Capability::Publish => "publish",
            Capability::Feeds => "feeds",
            Capability::Signing => "signing",
            Capability::Messaging => "messaging",
        }
    }

    pub fn from_key(key: &str) -> Option<Capability> {
        Capability::ALL.into_iter().find(|c| c.key() == key)
    }

    /// `CAPABILITY_META[key].label`.
    fn label(self) -> &'static str {
        match self {
            Capability::Publish => "Publish content",
            Capability::Feeds => "Manage feeds",
            Capability::Signing => "Sign Swarm content",
            Capability::Messaging => "Send and receive messages",
        }
    }

    /// `CAPABILITY_META[key].detail`.
    fn detail(self) -> &'static str {
        match self {
            Capability::Publish => "Use your postage stamps and bandwidth.",
            Capability::Feeds => "Create and update app feeds without repeated approval.",
            Capability::Signing => "Use an app-scoped publisher identity.",
            Capability::Messaging => "Use PSS and GSOC messaging.",
        }
    }

    /// `PROJECTIONS[key]`.
    fn projections(self) -> &'static [Projection] {
        match self {
            Capability::Publish => &[
                Projection::Connection,
                Projection::AutoApprove(Capability::Publish),
            ],
            Capability::Feeds => &[
                Projection::Connection,
                Projection::Identity,
                Projection::FeedGrant,
                Projection::AutoApprove(Capability::Feeds),
            ],
            Capability::Signing => &[
                Projection::Connection,
                Projection::Identity,
                Projection::FeedGrant,
                Projection::AutoApprove(Capability::Signing),
            ],
            Capability::Messaging => &[
                Projection::Connection,
                Projection::MessagingGrant,
                Projection::AutoApprove(Capability::Messaging),
            ],
        }
    }

    /// Feeds and signing need a publisher identity.
    fn needs_identity(self) -> bool {
        matches!(self, Capability::Feeds | Capability::Signing)
    }
}

/// A grant a manifest can manage for a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Projection {
    /// The Swarm connection (0012's `swarm-permissions.json`).
    Connection,
    /// The site's publisher identity (the feed store).
    Identity,
    /// The feed grant (the feed store).
    FeedGrant,
    /// The messaging grant (0012).
    MessagingGrant,
    /// An auto-approve flag (0012).
    AutoApprove(Capability),
}

impl Projection {
    pub fn key(self) -> &'static str {
        match self {
            Projection::Connection => "connection",
            Projection::Identity => "identity",
            Projection::FeedGrant => "feedGrant",
            Projection::MessagingGrant => "messagingGrant",
            Projection::AutoApprove(Capability::Publish) => "autoApprove.publish",
            Projection::AutoApprove(Capability::Feeds) => "autoApprove.feeds",
            Projection::AutoApprove(Capability::Signing) => "autoApprove.signing",
            Projection::AutoApprove(Capability::Messaging) => "autoApprove.messaging",
        }
    }

    pub fn from_key(key: &str) -> Option<Projection> {
        [
            Projection::Connection,
            Projection::Identity,
            Projection::FeedGrant,
            Projection::MessagingGrant,
        ]
        .into_iter()
        .chain(Capability::ALL.map(Projection::AutoApprove))
        .find(|p| p.key() == key)
    }

    /// `IDENTITY_PROJECTIONS`: the ones that mean something only with a
    /// usable publisher identity.
    fn needs_identity(self) -> bool {
        matches!(
            self,
            Projection::Identity
                | Projection::FeedGrant
                | Projection::AutoApprove(Capability::Feeds | Capability::Signing)
        )
    }
}

/// A projection turned on or off: one step of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operation {
    pub projection: Projection,
    pub enabled: bool,
}

impl Operation {
    fn json(self) -> JsValue {
        let mut out = object();
        out.set("projection", text(self.projection.key()));
        out.set("enabled", JsValue::Bool(self.enabled));
        out
    }
}

/// What applying an [`Operation`] changes, read against the grants and the
/// feed store as they stand (`applyProjectionValue`, with
/// `swarm-permissions.js`'s and `feed-store.js`'s own checks). Each is
/// main's own change (`shell`, naming the key: design 0012, "The model"),
/// and changes nothing it doesn't name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// `grantPermission(key, { source: 'manifest' })`: a connection, for a
    /// site without one.
    Connect,
    /// `revokePermission`: the connection, which the site has, removed.
    Disconnect,
    /// `setAutoApprove(key, capability, enabled)`, for a connected site.
    Flag {
        capability: Capability,
        enabled: bool,
    },
    /// `grantMessaging`, for a connected site, or `revokeMessaging`, for a
    /// site that holds it.
    Messaging(bool),
    /// `grantFeedAccess` or `revokeFeedAccess` with `source: 'manifest'`
    /// ([`FeedStore::grant_feed_access`]).
    FeedGrant(bool),
    /// `createAppScopedIdentity(key, { activate: true, source: 'manifest'
    /// })`, for a site without an identity.
    CreateIdentity,
}

/// What a manifest change reads outside its file: the Swarm grants (0012)
/// and the feed store.
pub trait Reads {
    /// `permissions.getPermission(key)`: the site is connected.
    fn connected(&self, key: &JsString) -> bool;
    /// `permissions.hasMessagingGrant(key)`.
    fn messaging(&self, key: &JsString) -> bool;
    /// `permissions.getAutoApprove(key, capability)`.
    fn auto_approve(&self, key: &JsString, capability: Capability) -> bool;
    /// The feed store, as it stands.
    fn feeds(&self) -> &FeedStore;
}

/// Where a manifest change's effects go: the store's file, and each
/// projection's grant. The daemon writes the file with 0001's durable write
/// and applies each effect to 0012's Swarm grants or the feed store (and
/// writes that).
pub trait World: Reads {
    type Error;
    /// Applies one projection's effect, as `applyProjectionValue` does.
    fn apply(&mut self, key: &JsString, effect: Effect) -> Result<(), ManifestError<Self::Error>>;
    /// Writes the store's file (`saveStore`).
    fn save(&mut self, save: &Save) -> Result<(), Self::Error>;
}

/// One write of the store's file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Save {
    /// The file's text.
    pub text: String,
    /// Copy the file as it stands, if there is one, to [`BACKUP_NAME`]
    /// first: always, unless the store was read from that backup and
    /// hasn't been written since.
    pub backup: bool,
}

/// Why a manifest operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError<E> {
    /// The reference's own refusal.
    #[error(transparent)]
    Thrown(Thrown),
    /// A write would pass the store's bound (`store_full`).
    #[error("the store's file would pass its bound")]
    Full,
    /// The store isn't loaded: none was yet, or its last write failed
    /// (the reference's `storeCache = null`). The daemon loads it again
    /// ([`ManifestStore::load`]) from the file.
    #[error("the manifest store is not loaded")]
    NotLoaded,
    /// The world's own failure: a write, or a grant change.
    #[error("the manifest store's world failed")]
    World(E),
}

impl<E> From<Thrown> for ManifestError<E> {
    fn from(thrown: Thrown) -> Self {
        ManifestError::Thrown(thrown)
    }
}

/// Why neither the file nor its backup is read: every operation fails until
/// one can be (the reference throws the file's parse error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("swarm-manifest-grants.json and its backup are unreadable")]
pub struct Unreadable;

/// Whose consent a check issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// Main's own, for a page's request (`checkPageManifest`): single-use,
    /// never shared or replayed, at most [`MAX_PAGE_TOKENS`] waiting.
    Page,
    /// An in-process caller's: shared between identical checks, and a
    /// decided one replayed.
    InProcess,
}

/// What [`ManifestStore::check`] answers.
#[derive(Debug, Clone, PartialEq)]
pub enum CheckStep {
    /// The check's answer.
    Done(JsValue),
    /// Fetch the manifest at `fetch.url` (`bzz://<host>/freedom-manifest.json`),
    /// then hand the answer to [`ManifestStore::check_fetched`].
    Fetch(ManifestFetch),
}

/// A check waiting on its manifest: what it read before the fetch.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestFetch {
    pub url: String,
    key: JsString,
    committed_url: String,
    owner: Owner,
    existing: Option<JsValue>,
    first_contact: bool,
    failures: u32,
}

/// The fetch's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetched<'a> {
    /// No answer: the fetch threw, or the body stalled or broke (a
    /// transport failure).
    Failed,
    /// The node's answer: its status and its body, of which at most
    /// [`MAX_MANIFEST_BYTES`] + 1 bytes are needed.
    Answered { status: u16, body: &'a [u8] },
}

/// What `discover` found.
enum Discovered {
    Unsupported,
    Unresolved,
    Absent,
    Invalid,
    Found(Found),
}

struct Found {
    manifest: Manifest,
    raw_hash: String,
    fingerprint: String,
}

/// A manifest as `validateManifest` returns it.
#[derive(Debug, Clone, PartialEq)]
struct Manifest {
    name: JsString,
    description: JsString,
    /// In `CAPABILITY_KEYS` order, each with its reason.
    capabilities: Vec<(Capability, JsString)>,
}

impl Manifest {
    fn why(&self, capability: Capability) -> JsValue {
        self.capabilities
            .iter()
            .find(|(c, _)| *c == capability)
            .map_or(JsValue::Undefined, |(_, why)| JsValue::String(why.clone()))
    }

    /// `manifest.capabilities`: `{ [key]: { why } }`.
    fn capabilities_json(&self) -> JsValue {
        let mut out = object();
        for (capability, why) in &self.capabilities {
            let mut row = object();
            row.set("why", JsValue::String(why.clone()));
            out.set(capability.key(), row);
        }
        out
    }
}

/// A consent waiting on its decision.
#[derive(Debug, Clone, PartialEq)]
struct Pending {
    origin: JsString,
    manifest: Manifest,
    fingerprint: String,
    raw_hash: String,
    base_revision: f64,
    first_contact: bool,
    changed: Vec<Capability>,
    expires_at: u64,
}

impl Pending {
    /// `sameConsent`.
    fn same(&self, other: &Pending) -> bool {
        self.origin == other.origin
            && self.fingerprint == other.fingerprint
            && self.base_revision == other.base_revision
            && self.changed == other.changed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Backoff {
    failures: u32,
    retry_at: u64,
}

/// The manifest store, and the consents and backoff the reference keeps in
/// memory.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ManifestStore {
    /// The file's object (`storeCache`); `None` until loaded, and after a
    /// failed write.
    doc: Option<JsValue>,
    loaded_from_backup: bool,
    tokens: Vec<(String, Pending)>,
    completed: Vec<(String, JsValue)>,
    page_tokens: Vec<(String, Pending)>,
    backoff: Vec<(JsString, Backoff)>,
}

fn empty_doc() -> JsValue {
    let mut doc = object();
    doc.set("version", JsValue::Number(1.0));
    doc.set("records", object());
    doc
}

/// `{ ...emptyStore(), ...JSON.parse(text) }`, within the bound and the
/// shape the core reads.
fn read_doc(bytes: &[u8]) -> Option<JsValue> {
    if bytes.len() > MAX_FILE_BYTES {
        return None;
    }
    let parsed = parse_file(bytes)?;
    if !is_plain_object(&parsed) {
        return None;
    }
    let mut doc = empty_doc();
    super::spread_into(&mut doc, &parsed);
    readable(&doc).then_some(doc)
}

/// The shape the core reads (module docs).
fn readable(doc: &JsValue) -> bool {
    let records_ok = match doc.get("records") {
        Some(JsValue::Object(records)) => records.iter().all(|(_, r)| readable_record(r)),
        _ => false,
    };
    let pending_ok = match doc.get("pending") {
        None => true,
        Some(pending) if !pending.truthy() => true,
        Some(pending @ JsValue::Object(_)) => {
            matches!(pending.get("origin"), Some(JsValue::String(_)))
                && match pending.get("record") {
                    None | Some(JsValue::Null) => true,
                    Some(record) => readable_record(record),
                }
                && match pending.get("operations") {
                    Some(JsValue::Array(ops)) => ops.iter().all(|op| read_operation(op).is_some()),
                    _ => false,
                }
        }
        Some(_) => false,
    };
    records_ok && pending_ok
}

fn readable_record(record: &JsValue) -> bool {
    if !is_plain_object(record) {
        return false;
    }
    let managed_ok = match record.get("managed") {
        None => true,
        Some(m) if !m.truthy() => true,
        Some(JsValue::Object(m)) => m.iter().all(|(projection, owners)| {
            Projection::from_key(projection.as_str()).is_some()
                && projection.is_well_formed()
                && matches!(owners, JsValue::Array(_))
        }),
        Some(_) => false,
    };
    let acknowledged_ok = match record.get("acknowledged") {
        Some(JsValue::Object(a)) => a
            .iter()
            .all(|(c, _)| c.is_well_formed() && Capability::from_key(c.as_str()).is_some()),
        _ => false,
    };
    let detached_ok = match record.get("detached") {
        None => true,
        Some(d) => !d.truthy() || is_plain_object(d),
    };
    let revision_ok = matches!(
        record.get("revision"),
        None | Some(JsValue::Null | JsValue::Number(_))
    );
    let receipts_ok = match record.get("receipts") {
        None => true,
        Some(r) => !r.truthy() || matches!(r, JsValue::Array(_)),
    };
    managed_ok && acknowledged_ok && detached_ok && revision_ok && receipts_ok
}

fn read_operation(op: &JsValue) -> Option<Operation> {
    let projection = match op.get("projection") {
        Some(JsValue::String(p)) if p.is_well_formed() => Projection::from_key(p.as_str())?,
        _ => return None,
    };
    let Some(JsValue::Bool(enabled)) = op.get("enabled") else {
        return None;
    };
    Some(Operation {
        projection,
        enabled: *enabled,
    })
}

/// `record.revision || 0`, a number (the shape holds it to one).
fn revision_of(record: Option<&JsValue>) -> f64 {
    match record.and_then(|r| r.get("revision")) {
        Some(JsValue::Number(n)) if *n != 0.0 && !n.is_nan() => *n,
        _ => 0.0,
    }
}

impl ManifestStore {
    /// No store loaded yet, and no consent or backoff.
    pub fn new() -> Self {
        ManifestStore::default()
    }

    /// Whether the store is loaded.
    pub fn is_loaded(&self) -> bool {
        self.doc.is_some()
    }

    /// `loadStore()`: the file (`None` when there is none: an empty store,
    /// its backup unread), or where it isn't readable its backup, which
    /// `backup` reads (`None` when there is none).
    pub fn load(
        &mut self,
        file: Option<&[u8]>,
        backup: impl FnOnce() -> Option<Vec<u8>>,
    ) -> Result<(), Unreadable> {
        let Some(bytes) = file else {
            self.doc = Some(empty_doc());
            return Ok(());
        };
        if let Some(doc) = read_doc(bytes) {
            self.doc = Some(doc);
            return Ok(());
        }
        match backup().and_then(|bytes| read_doc(&bytes)) {
            Some(doc) => {
                self.doc = Some(doc);
                self.loaded_from_backup = true;
                Ok(())
            }
            None => Err(Unreadable),
        }
    }

    fn doc<E>(&self) -> Result<&JsValue, ManifestError<E>> {
        self.doc.as_ref().ok_or(ManifestError::NotLoaded)
    }

    fn doc_mut<E>(&mut self) -> Result<&mut JsValue, ManifestError<E>> {
        self.doc.as_mut().ok_or(ManifestError::NotLoaded)
    }

    /// `state.records[key]`, where truthy.
    fn record<E>(&self, key: &JsString) -> Result<Option<&JsValue>, ManifestError<E>> {
        Ok(self
            .doc()?
            .get("records")
            .and_then(|records| get(records, key))
            .filter(|record| record.truthy()))
    }

    fn records_mut<E>(&mut self) -> Result<&mut JsValue, ManifestError<E>> {
        self.doc_mut()?
            .get_mut("records")
            .ok_or(ManifestError::NotLoaded)
    }

    /// `saveStore()`: the file's text, the backup copy first unless read
    /// from it. A write that fails, or that would pass the bound, leaves
    /// the store unloaded.
    fn save<W: World>(&mut self, world: &mut W) -> Result<(), ManifestError<W::Error>> {
        let text = self.doc()?.stringify_pretty();
        if text.len() > MAX_FILE_BYTES {
            self.doc = None;
            return Err(ManifestError::Full);
        }
        let save = Save {
            text,
            backup: !self.loaded_from_backup,
        };
        if let Err(e) = world.save(&save) {
            self.doc = None;
            return Err(ManifestError::World(e));
        }
        self.loaded_from_backup = false;
        Ok(())
    }

    /// `runTransaction(origin, record, operations)`.
    fn run_transaction<W: World>(
        &mut self,
        world: &mut W,
        origin: &JsString,
        record: Option<JsValue>,
        operations: &[Operation],
    ) -> Result<(), ManifestError<W::Error>> {
        let mut pending = object();
        pending.set("origin", JsValue::String(origin.clone()));
        pending.set("record", record.clone().unwrap_or(JsValue::Null));
        pending.set(
            "operations",
            JsValue::Array(operations.iter().map(|op| op.json()).collect()),
        );
        self.doc_mut()?.set("pending", pending);
        self.save(world)?;
        for operation in operations {
            apply_operation(world, origin, *operation)?;
        }
        self.commit(origin, record)?;
        self.save(world)
    }

    /// The record in place of the journal: set, or removed for `None`.
    fn commit<E>(
        &mut self,
        origin: &JsString,
        record: Option<JsValue>,
    ) -> Result<(), ManifestError<E>> {
        let records = self.records_mut()?;
        match record {
            Some(record) => records.set(origin.clone(), record),
            None => {
                remove(records, origin);
            }
        }
        remove(self.doc_mut()?, &JsString::from("pending"));
        Ok(())
    }

    /// `recoverPending()`: a journal left by a crash or a failed step,
    /// replayed (`replayPending`). The core reads the Swarm grants itself,
    /// so they are always loaded (the reference waits until main has read
    /// them).
    pub fn recover_pending<W: World>(
        &mut self,
        world: &mut W,
    ) -> Result<(), ManifestError<W::Error>> {
        let Some(pending) = self.doc()?.get("pending").filter(|p| p.truthy()).cloned() else {
            return Ok(());
        };
        let origin = match pending.get("origin") {
            Some(JsValue::String(origin)) => origin.clone(),
            _ => return Ok(()),
        };
        let mut record = pending
            .get("record")
            .filter(|record| record.truthy())
            .cloned();
        let mut operations: Vec<Operation> = pending
            .get("operations")
            .and_then(JsValue::as_array)
            .unwrap_or(&[])
            .iter()
            .filter_map(read_operation)
            .collect();
        // `withoutUnavailableIdentity`.
        if world.feeds().has_unavailable_identity(&origin) {
            if let Some(managed) = record.as_mut().and_then(|r| r.get_mut("managed")) {
                for projection in all_projections().filter(|p| p.needs_identity()) {
                    remove(managed, &JsString::from(projection.key()));
                }
            }
            operations.retain(|op| !(op.enabled && op.projection.needs_identity()));
        }
        for operation in operations {
            apply_operation(world, &origin, operation)?;
        }
        self.commit(&origin, record)?;
        self.save(world)
    }

    // --- check ---------------------------------------------------------------

    /// `checkManifest({ origin, committedUrl, eager })` up to its fetch:
    /// the answer where the reference answers without one (no record and
    /// not eager, or within the unresolved backoff, or a committed URL that
    /// isn't `bzz:`), or the address to fetch.
    pub fn check<W: World>(
        &mut self,
        key: &JsString,
        committed_url: &str,
        eager: bool,
        owner: Owner,
        world: &mut W,
        now_ms: u64,
    ) -> Result<CheckStep, ManifestError<W::Error>> {
        self.recover_pending(world)?;
        let existing = self.record(key)?.cloned();
        let first_contact = existing.is_none() && !world.connected(key);
        if existing.is_none() && !eager {
            return Ok(CheckStep::Done(kind("legacy")));
        }
        let backoff = self.backoff.iter().find(|(k, _)| k == key).map(|(_, b)| *b);
        if let Some(backoff) = backoff.filter(|b| now_ms < b.retry_at) {
            let mut out = if existing.is_some() {
                kind("unresolved")
            } else {
                let mut out = kind("legacy");
                out.set("reason", text("unresolved-backoff"));
                out
            };
            out.set("retryAt", time(backoff.retry_at));
            return Ok(CheckStep::Done(out));
        }
        let fetch = ManifestFetch {
            url: String::new(),
            key: key.clone(),
            committed_url: committed_url.to_owned(),
            owner,
            existing,
            first_contact,
            failures: backoff.map_or(0, |b| b.failures),
        };
        match manifest_url(committed_url) {
            Some(url) => Ok(CheckStep::Fetch(ManifestFetch { url, ..fetch })),
            None => self
                .conclude(fetch, Discovered::Unsupported, world, now_ms, &mut || {
                    [0; 24]
                })
                .map(CheckStep::Done),
        }
    }

    /// The rest of the check, once the manifest was fetched: the answer,
    /// `legacy` (pruning the site's record if the manifest is gone or
    /// invalid), `unresolved`, `ready`, or a consent with its token, which
    /// `random` makes (24 bytes, `crypto.randomBytes(24)`).
    pub fn check_fetched<W: World>(
        &mut self,
        fetch: ManifestFetch,
        fetched: Fetched<'_>,
        world: &mut W,
        now_ms: u64,
        mut random: impl FnMut() -> [u8; 24],
    ) -> Result<JsValue, ManifestError<W::Error>> {
        self.conclude(fetch, discover(fetched), world, now_ms, &mut random)
    }

    fn conclude<W: World>(
        &mut self,
        fetch: ManifestFetch,
        found: Discovered,
        world: &mut W,
        now_ms: u64,
        random: &mut dyn FnMut() -> [u8; 24],
    ) -> Result<JsValue, ManifestError<W::Error>> {
        let key = &fetch.key;
        if matches!(found, Discovered::Unresolved) {
            let failures = fetch.failures.saturating_add(1);
            let step = usize::try_from(failures - 1)
                .unwrap_or(usize::MAX)
                .min(UNRESOLVED_BACKOFF_MS.len() - 1);
            let retry_at = now_ms.saturating_add(UNRESOLVED_BACKOFF_MS[step]);
            let entry = Backoff { failures, retry_at };
            match self.backoff.iter_mut().find(|(k, _)| k == key) {
                Some((_, b)) => *b = entry,
                None => self.backoff.push((key.clone(), entry)),
            }
            let mut out = if fetch.existing.is_some() {
                kind("unresolved")
            } else {
                let mut out = kind("legacy");
                out.set("reason", text("unresolved"));
                out
            };
            out.set("retryAt", time(retry_at));
            return Ok(out);
        }
        self.backoff.retain(|(k, _)| k != key);
        if normalize_origin(&fetch.committed_url) != key.as_str() || !key.is_well_formed() {
            return Ok(kind("legacy"));
        }
        let found = match found {
            Discovered::Found(found) => found,
            other => {
                let reason = match other {
                    Discovered::Unsupported => "unsupported",
                    Discovered::Absent => "absent",
                    _ => "invalid",
                };
                if fetch.existing.is_some() {
                    self.prune_record(world, key)?;
                }
                let mut out = kind("legacy");
                out.set("pruned", JsValue::Bool(fetch.existing.is_some()));
                out.set("reason", text(reason));
                return Ok(out);
            }
        };
        self.conclude_found(fetch, found, world, now_ms, random)
    }

    fn conclude_found<W: World>(
        &mut self,
        fetch: ManifestFetch,
        found: Found,
        world: &mut W,
        now_ms: u64,
        random: &mut dyn FnMut() -> [u8; 24],
    ) -> Result<JsValue, ManifestError<W::Error>> {
        let key = fetch.key.clone();
        let manifest = found.manifest;
        let next: Vec<Capability> = manifest.capabilities.iter().map(|(c, _)| *c).collect();
        let acknowledged = fetch
            .existing
            .as_ref()
            .and_then(|e| e.get("acknowledged"))
            .filter(|a| a.truthy())
            .cloned()
            .unwrap_or_else(object);
        let removed: Vec<Capability> = props(&acknowledged)
            .iter()
            .filter_map(|(c, _)| Capability::from_key(c.as_str()))
            .filter(|c| !next.contains(c))
            .collect();
        let additions: Vec<Capability> = next
            .iter()
            .copied()
            .filter(|c| !truthy(acknowledged.get(c.key())))
            .collect();
        let mut record = fetch.existing.clone().unwrap_or_else(new_record);
        let removal_operations = remove_owners(&mut record, &removed);
        if let Some(acknowledged) = record.get_mut("acknowledged") {
            for capability in &removed {
                remove(acknowledged, &JsString::from(capability.key()));
            }
        }
        let mut observed = object();
        observed.set("fingerprint", text(&found.fingerprint));
        observed.set("rawHash", text(&found.raw_hash));
        observed.set("capabilities", manifest.capabilities_json());
        observed.set("checkedAt", time(now_ms));
        record.set("observed", observed);
        let mut app = object();
        app.set("name", JsValue::String(manifest.name.clone()));
        app.set("description", JsValue::String(manifest.description.clone()));
        record.set("app", app);
        let satisfied: Vec<Capability> = additions
            .iter()
            .copied()
            .filter(|c| {
                c.projections()
                    .iter()
                    .all(|p| current_value(&*world, &key, *p))
            })
            .collect();
        for capability in &satisfied {
            let mut decision = object();
            decision.set("decision", text("individual"));
            decision.set("source", text("existing-grant"));
            decision.set("decidedAt", time(now_ms));
            if let Some(acknowledged) = record.get_mut("acknowledged") {
                acknowledged.set(capability.key(), decision);
            }
        }
        let changed: Vec<Capability> = additions
            .iter()
            .copied()
            .filter(|c| !satisfied.contains(c))
            .collect();
        let mut revision = revision_of(fetch.existing.as_ref());
        if !removal_operations.is_empty() || !removed.is_empty() || !satisfied.is_empty() {
            revision += 1.0;
            record.set("revision", JsValue::Number(revision));
            self.run_transaction(world, &key, Some(record), &removal_operations)?;
        } else {
            record.set("revision", JsValue::Number(revision));
            self.records_mut()?.set(key.clone(), record);
            self.save(world)?;
        }
        if changed.is_empty() {
            return Ok(kind("ready"));
        }
        let pending = Pending {
            origin: key.clone(),
            manifest,
            fingerprint: found.fingerprint,
            raw_hash: found.raw_hash,
            base_revision: revision,
            first_contact: fetch.first_contact,
            changed,
            expires_at: now_ms.saturating_add(TOKEN_TTL_MS),
        };
        let model = consent_model(
            &*world,
            &key,
            fetch.existing.is_some(),
            &pending.manifest,
            &pending.changed,
            &removed,
        );
        let token = match fetch.owner {
            Owner::Page => {
                self.sweep_page_tokens(now_ms);
                while self.page_tokens.len() >= MAX_PAGE_TOKENS {
                    self.page_tokens.remove(0);
                }
                let token = base64url(&random());
                self.page_tokens.push((token.clone(), pending));
                token
            }
            Owner::InProcess => match self.outstanding_token(&pending, now_ms) {
                Some(index) => {
                    let (token, waiting) = &mut self.tokens[index];
                    waiting.expires_at = pending.expires_at;
                    token.clone()
                }
                None => {
                    let token = base64url(&random());
                    self.tokens.push((token.clone(), pending));
                    token
                }
            },
        };
        let mut out = kind("consent");
        out.set("token", text(&token));
        out.set("model", model);
        Ok(out)
    }

    /// `outstandingToken(candidate)`: the first waiting consent the same as
    /// `candidate`, expired ones dropped on the way.
    fn outstanding_token(&mut self, candidate: &Pending, now_ms: u64) -> Option<usize> {
        self.tokens
            .retain(|(_, pending)| pending.expires_at >= now_ms);
        self.tokens
            .iter()
            .position(|(_, pending)| pending.same(candidate))
    }

    /// `sweepPageTokens()`.
    fn sweep_page_tokens(&mut self, now_ms: u64) {
        self.page_tokens
            .retain(|(_, pending)| pending.expires_at >= now_ms);
    }

    /// `releasePageManifest(token)`: a page's consent spent, however its
    /// request ended.
    pub fn release_page_token(&mut self, token: &str) {
        self.page_tokens.retain(|(t, _)| t != token);
    }

    /// Whether `token` is a page consent waiting for `key`
    /// (`decidePageManifest`'s first check: otherwise `Manifest consent
    /// expired`).
    pub fn page_token_is_for(&mut self, token: &str, key: &JsString, now_ms: u64) -> bool {
        self.sweep_page_tokens(now_ms);
        self.page_tokens
            .iter()
            .any(|(t, pending)| t == token && pending.origin == *key)
    }

    /// `pruneRecord(origin)`: every capability's projections let go of, and
    /// the record removed.
    fn prune_record<W: World>(
        &mut self,
        world: &mut W,
        key: &JsString,
    ) -> Result<(), ManifestError<W::Error>> {
        let Some(record) = get_mut(self.records_mut()?, key).filter(|record| record.truthy())
        else {
            return Ok(());
        };
        // The live record changes, so the journal shows it so.
        let operations = remove_owners(record, &Capability::ALL);
        self.run_transaction(world, key, None, &operations)
    }

    // --- decide ----------------------------------------------------------------

    /// `decideManifest(token, outcome, { owner })`: `allow` lets the
    /// manifest manage the changed capabilities' projections, `individual`
    /// keeps each to its own prompt (and connects the site), `deny` changes
    /// nothing but drops a first contact's record.
    pub fn decide<W: World>(
        &mut self,
        token: &str,
        outcome: &str,
        owner: Owner,
        world: &mut W,
        now_ms: u64,
    ) -> Result<JsValue, ManifestError<W::Error>> {
        self.recover_pending(world)?;
        let for_page = owner == Owner::Page;
        if for_page {
            self.sweep_page_tokens(now_ms);
        } else if let Some((_, result)) = self.completed.iter().find(|(t, _)| t == token) {
            return Ok(result.clone());
        }
        let pool = if for_page {
            &mut self.page_tokens
        } else {
            &mut self.tokens
        };
        let at = pool.iter().position(|(t, _)| t == token);
        let Some(pending) = at
            .map(|at| pool[at].1.clone())
            .filter(|pending| pending.expires_at >= now_ms)
        else {
            pool.retain(|(t, _)| t != token);
            return Err(Thrown::error("Manifest consent expired").into());
        };
        let outcome = match outcome {
            "allow" => Outcome::Allow,
            "individual" => Outcome::Individual,
            "deny" => Outcome::Deny,
            _ => return Err(Thrown::error("Invalid manifest decision").into()),
        };
        let current = self.record(&pending.origin)?;
        let fingerprint = current
            .and_then(|r| r.get("observed"))
            .and_then(|o| o.get("fingerprint"));
        let fresh = matches!(fingerprint, Some(JsValue::String(f)) if f == pending.fingerprint.as_str())
            && revision_of(current) == pending.base_revision;
        if !fresh {
            self.pool_mut(owner).retain(|(t, _)| t != token);
            return Err(Thrown::error("Manifest consent is stale").into());
        }
        let mut record = current.cloned().unwrap_or_else(new_record);
        let origin = pending.origin.clone();
        let mut operations = Vec::new();
        if outcome != Outcome::Deny {
            if outcome == Outcome::Individual {
                detach_connection(&mut record);
                if !world.connected(&origin) {
                    operations.push(Operation {
                        projection: Projection::Connection,
                        enabled: true,
                    });
                }
            }
            if outcome == Outcome::Allow && pending.changed.iter().any(|c| c.needs_identity()) {
                world.feeds().assert_feed_grantable(&origin)?;
            }
            for capability in &pending.changed {
                let mut decision = object();
                decision.set(
                    "decision",
                    text(if outcome == Outcome::Allow {
                        "managed"
                    } else {
                        "individual"
                    }),
                );
                decision.set("source", text("sheet"));
                decision.set("whyShown", pending.manifest.why(*capability));
                decision.set("decidedAt", time(now_ms));
                if let Some(acknowledged) = record.get_mut("acknowledged") {
                    acknowledged.set(capability.key(), decision);
                }
                if outcome == Outcome::Allow {
                    operations.extend(add_managed_capability(
                        &*world,
                        &origin,
                        &mut record,
                        *capability,
                    ));
                } else {
                    operations.extend(remove_owners(&mut record, &[*capability]));
                }
            }
            if !truthy(record.get("receipts")) {
                record.set("receipts", JsValue::Array(Vec::new()));
            }
            let receipt = receipt(&pending, outcome, now_ms);
            if let Some(JsValue::Array(receipts)) = record.get_mut("receipts") {
                receipts.push(receipt);
                let excess = receipts.len().saturating_sub(MAX_RECEIPTS);
                receipts.drain(..excess);
            }
            record.set("revision", JsValue::Number(pending.base_revision + 1.0));
            self.run_transaction(world, &origin, Some(record), &operations)?;
        } else if pending.first_contact {
            self.run_transaction(world, &origin, None, &[])?;
        }
        let mut result = object();
        result.set("allowed", JsValue::Bool(outcome != Outcome::Deny));
        result.set("mode", text(outcome.key()));
        self.pool_mut(owner).retain(|(t, _)| t != token);
        if !for_page {
            self.completed.push((token.to_owned(), result.clone()));
            if self.completed.len() > MAX_COMPLETED {
                self.completed.remove(0);
            }
        }
        Ok(result)
    }

    fn pool_mut(&mut self, owner: Owner) -> &mut Vec<(String, Pending)> {
        match owner {
            Owner::Page => &mut self.page_tokens,
            Owner::InProcess => &mut self.tokens,
        }
    }

    // --- the chrome's -------------------------------------------------------------

    /// `useIndividual(key, capability)`: a managed capability handed back
    /// to its own prompts. `false` where the site never acknowledged it.
    pub fn use_individual<W: World>(
        &mut self,
        key: &JsString,
        capability: &JsValue,
        world: &mut W,
        now_ms: u64,
    ) -> Result<bool, ManifestError<W::Error>> {
        self.recover_pending(world)?;
        let capability = match capability {
            JsValue::String(c) if c.is_well_formed() => Capability::from_key(c.as_str()),
            _ => None,
        }
        .ok_or_else(|| Thrown::error("Unknown capability"))?;
        let Some(mut record) = self.record(key)?.cloned() else {
            return Ok(false);
        };
        let acknowledged = record
            .get("acknowledged")
            .and_then(|a| a.get(capability.key()))
            .filter(|a| a.truthy())
            .cloned();
        let Some(acknowledged) = acknowledged else {
            return Ok(false);
        };
        detach_connection(&mut record);
        let operations = remove_owners(&mut record, &[capability]);
        let mut decision = spread(&acknowledged);
        decision.set("decision", text("individual"));
        decision.set("decidedAt", time(now_ms));
        if let Some(acknowledged) = record.get_mut("acknowledged") {
            acknowledged.set(capability.key(), decision);
        }
        let revision = revision_of(Some(&record)) + 1.0;
        record.set("revision", JsValue::Number(revision));
        self.run_transaction(world, key, Some(record), &operations)?;
        Ok(true)
    }

    /// `disconnect(key)`: the record removed, and the feed grant and the
    /// connection revoked.
    pub fn disconnect<W: World>(
        &mut self,
        key: &JsString,
        world: &mut W,
    ) -> Result<bool, ManifestError<W::Error>> {
        self.recover_pending(world)?;
        self.run_transaction(
            world,
            key,
            None,
            &[
                Operation {
                    projection: Projection::FeedGrant,
                    enabled: false,
                },
                Operation {
                    projection: Projection::Connection,
                    enabled: false,
                },
            ],
        )?;
        Ok(true)
    }

    /// `getRecord(key)`: a copy of the site's record, or `null`.
    pub fn get_record<W: World>(
        &mut self,
        key: &JsString,
        world: &mut W,
    ) -> Result<JsValue, ManifestError<W::Error>> {
        self.recover_pending(world)?;
        Ok(self.record(key)?.cloned().unwrap_or(JsValue::Null))
    }

    /// `detachManaged(key, projection)`: the user changed a projection a
    /// manifest manages (the feed store's and the Swarm grants' reports):
    /// the record lets go of it and won't take it back. A connection
    /// changed by hand disconnects.
    pub fn detach_managed<W: World>(
        &mut self,
        key: &JsString,
        projection: Projection,
        world: &mut W,
    ) -> Result<(), ManifestError<W::Error>> {
        if projection == Projection::Connection {
            return self.disconnect(key, world).map(drop);
        }
        self.recover_pending(world)?;
        let Some(record) = get_mut(self.records_mut()?, key).filter(|record| record.truthy())
        else {
            return Ok(());
        };
        // The live record changes before its journal, as the reference's.
        if !truthy(record.get("detached")) {
            record.set("detached", object());
        }
        if let Some(detached) = record.get_mut("detached") {
            detached.set(projection.key(), JsValue::Bool(true));
        }
        if truthy(record.get("managed"))
            && let Some(managed) = record.get_mut("managed")
        {
            remove(managed, &JsString::from(projection.key()));
        }
        let revision = revision_of(Some(record)) + 1.0;
        record.set("revision", JsValue::Number(revision));
        let record = record.clone();
        self.run_transaction(world, key, Some(record), &[])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Allow,
    Individual,
    Deny,
}

impl Outcome {
    fn key(self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Individual => "individual",
            Outcome::Deny => "deny",
        }
    }
}

fn kind(kind: &str) -> JsValue {
    let mut out = object();
    out.set("kind", text(kind));
    out
}

/// `{ managed: {}, acknowledged: {} }`.
fn new_record() -> JsValue {
    let mut record = object();
    record.set("managed", object());
    record.set("acknowledged", object());
    record
}

fn all_projections() -> impl Iterator<Item = Projection> {
    [
        Projection::Connection,
        Projection::Identity,
        Projection::FeedGrant,
        Projection::MessagingGrant,
    ]
    .into_iter()
    .chain(Capability::ALL.map(Projection::AutoApprove))
}

/// `record.detached ||= {}; record.detached.connection = true; delete
/// record.managed?.connection`.
fn detach_connection(record: &mut JsValue) {
    if !truthy(record.get("detached")) {
        record.set("detached", object());
    }
    if let Some(detached) = record.get_mut("detached") {
        detached.set("connection", JsValue::Bool(true));
    }
    if let Some(managed) = record.get_mut("managed") {
        remove(managed, &JsString::from("connection"));
    }
}

/// `record.managed ||= {}`.
fn managed_mut(record: &mut JsValue) -> Option<&mut JsValue> {
    if !truthy(record.get("managed")) {
        record.set("managed", object());
    }
    record.get_mut("managed")
}

/// `removeOwners(record, capabilities)`: each projection's owners less
/// `capabilities`; a projection left with none goes, and is turned off
/// (the identity stays), the connection last.
fn remove_owners(record: &mut JsValue, capabilities: &[Capability]) -> Vec<Operation> {
    let mut operations = Vec::new();
    let Some(managed) = managed_mut(record) else {
        return operations;
    };
    let entries: Vec<(JsString, JsValue)> = props(managed).to_vec();
    for (projection, owners) in entries {
        let remaining: Vec<JsValue> = owners
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter(|owner| {
                !capabilities
                    .iter()
                    .any(|c| matches!(owner, JsValue::String(o) if o == c.key()))
            })
            .cloned()
            .collect();
        if remaining.is_empty() {
            match Projection::from_key(projection.as_str()) {
                Some(Projection::Identity) | None => {}
                Some(p) => operations.push(Operation {
                    projection: p,
                    enabled: false,
                }),
            }
            remove(managed, &projection);
        } else {
            managed.set(projection, JsValue::Array(remaining));
        }
    }
    // A stable sort, the connection last.
    let (mut rest, connection): (Vec<Operation>, Vec<Operation>) = operations
        .into_iter()
        .partition(|op| op.projection != Projection::Connection);
    rest.extend(connection);
    rest
}

/// `addManagedCapability(origin, record, capability)`: the capability among
/// each of its projections' owners; a projection not on yet (and not
/// detached) owned by it alone, and turned on.
fn add_managed_capability(
    reads: &impl Reads,
    key: &JsString,
    record: &mut JsValue,
    capability: Capability,
) -> Vec<Operation> {
    let mut operations = Vec::new();
    let detached = record.get("detached").cloned();
    let Some(managed) = managed_mut(record) else {
        return operations;
    };
    for projection in capability.projections() {
        if detached
            .as_ref()
            .is_some_and(|d| truthy(d.get(projection.key())))
        {
            continue;
        }
        let owners = managed
            .get(projection.key())
            .filter(|o| o.truthy())
            .and_then(JsValue::as_array)
            .map(<[JsValue]>::to_vec)
            .unwrap_or_default();
        if !owners.is_empty() {
            if !owners
                .iter()
                .any(|o| matches!(o, JsValue::String(s) if s == capability.key()))
            {
                let mut next = owners;
                next.push(text(capability.key()));
                managed.set(projection.key(), JsValue::Array(next));
            }
            continue;
        }
        if !current_value(reads, key, *projection) {
            managed.set(
                projection.key(),
                JsValue::Array(vec![text(capability.key())]),
            );
            operations.push(Operation {
                projection: *projection,
                enabled: true,
            });
        }
    }
    operations
}

/// `currentProjectionValue(origin, projection)`.
fn current_value(reads: &impl Reads, key: &JsString, projection: Projection) -> bool {
    match projection {
        Projection::Connection => reads.connected(key),
        Projection::FeedGrant => reads.feeds().has_feed_grant(key),
        Projection::Identity => reads.feeds().has_identity_mode(key),
        Projection::MessagingGrant => reads.messaging(key),
        Projection::AutoApprove(capability) => reads.auto_approve(key, capability),
    }
}

/// `applyProjectionValue(origin, projection, enabled)`: the effect, if any,
/// read against the state now.
pub fn effect_of(reads: &impl Reads, key: &JsString, operation: Operation) -> Option<Effect> {
    let enabled = operation.enabled;
    match operation.projection {
        Projection::Connection => match (enabled, reads.connected(key)) {
            (true, false) => Some(Effect::Connect),
            (false, true) => Some(Effect::Disconnect),
            _ => None,
        },
        Projection::FeedGrant => Some(Effect::FeedGrant(enabled)),
        Projection::Identity => {
            (enabled && !reads.feeds().has_identity_mode(key)).then_some(Effect::CreateIdentity)
        }
        Projection::MessagingGrant => {
            let applies = if enabled {
                reads.connected(key)
            } else {
                reads.messaging(key)
            };
            applies.then_some(Effect::Messaging(enabled))
        }
        Projection::AutoApprove(capability) => reads.connected(key).then_some(Effect::Flag {
            capability,
            enabled,
        }),
    }
}

fn apply_operation<W: World>(
    world: &mut W,
    key: &JsString,
    operation: Operation,
) -> Result<(), ManifestError<W::Error>> {
    match effect_of(&*world, key, operation) {
        Some(effect) => world.apply(key, effect),
        None => Ok(()),
    }
}

/// `buildConsentModel(origin, record, manifest, changed, removed)`.
fn consent_model(
    reads: &impl Reads,
    key: &JsString,
    is_update: bool,
    manifest: &Manifest,
    changed: &[Capability],
    removed: &[Capability],
) -> JsValue {
    let mut out = object();
    out.set("origin", JsValue::String(key.clone()));
    out.set("name", JsValue::String(manifest.name.clone()));
    out.set("description", JsValue::String(manifest.description.clone()));
    out.set(
        "changed",
        JsValue::Array(
            changed
                .iter()
                .map(|c| {
                    let mut row = object();
                    row.set("key", text(c.key()));
                    row.set("label", text(c.label()));
                    row.set("detail", text(c.detail()));
                    row.set("why", manifest.why(*c));
                    row
                })
                .collect(),
        ),
    );
    out.set(
        "removed",
        JsValue::Array(
            removed
                .iter()
                .map(|c| {
                    let mut row = object();
                    row.set("key", text(c.key()));
                    row.set("label", text(c.label()));
                    row
                })
                .collect(),
        ),
    );
    let identity = changed.iter().any(|c| c.needs_identity());
    let has_identity = reads.feeds().has_identity_mode(key);
    out.set("createsIdentity", JsValue::Bool(identity && !has_identity));
    out.set("preservedIdentity", JsValue::Bool(identity && has_identity));
    out.set("isUpdate", JsValue::Bool(is_update));
    out
}

/// A decision's receipt.
fn receipt(pending: &Pending, outcome: Outcome, now_ms: u64) -> JsValue {
    let mut receipt = object();
    receipt.set("decidedAt", time(now_ms));
    receipt.set(
        "outcome",
        text(if outcome == Outcome::Allow {
            "managed"
        } else {
            "individual"
        }),
    );
    receipt.set("originShown", JsValue::String(pending.origin.clone()));
    receipt.set(
        "manifestNameShown",
        JsValue::String(pending.manifest.name.clone()),
    );
    receipt.set(
        "manifestDescriptionShown",
        JsValue::String(pending.manifest.description.clone()),
    );
    receipt.set(
        "rows",
        JsValue::Array(
            pending
                .changed
                .iter()
                .map(|c| {
                    let mut row = object();
                    row.set("capability", text(c.key()));
                    row.set("browserLabelVersion", JsValue::Number(1.0));
                    row.set("whyShown", pending.manifest.why(*c));
                    row
                })
                .collect(),
        ),
    );
    receipt.set("rawHash", text(&pending.raw_hash));
    receipt
}

// --- the manifest ---------------------------------------------------------------

/// `bzz://${url.host}/freedom-manifest.json` for a committed URL that the
/// WHATWG parser reads as `bzz:`; `None` for any other (`unsupported`).
pub fn manifest_url(committed_url: &str) -> Option<String> {
    let url = url::Url::parse(committed_url).ok()?;
    if url.scheme() != "bzz" {
        return None;
    }
    let host = url.host_str().unwrap_or("");
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Some(format!("bzz://{host}/freedom-manifest.json"))
}

/// `discover`'s verdict on the fetch's outcome.
fn discover(fetched: Fetched<'_>) -> Discovered {
    let (status, body) = match fetched {
        Fetched::Failed => return Discovered::Unresolved,
        Fetched::Answered { status, body } => (status, body),
    };
    if status == 404 {
        return Discovered::Absent;
    }
    if !(200..=299).contains(&status) {
        return if (400..500).contains(&status) {
            Discovered::Invalid
        } else {
            Discovered::Unresolved
        };
    }
    match read_manifest(body) {
        Some(found) => Discovered::Found(found),
        None => Discovered::Invalid,
    }
}

/// `readLimitedJson` and `validateManifest` over the body.
fn read_manifest(body: &[u8]) -> Option<Found> {
    if body.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    // `new TextDecoder('utf-8', { fatal: true })`: a byte-order mark
    // dropped, any bad sequence refused.
    let text = std::str::from_utf8(crate::js::strip_bom(body)).ok()?;
    let value = fc_json::parse(text).ok()?;
    let manifest = validate_manifest(&value).ok()?;
    let raw_hash = hex(&Sha256::digest(body));
    let fingerprint = fingerprint(&manifest);
    Some(Found {
        manifest,
        raw_hash,
        fingerprint,
    })
}

/// `fingerprint(manifest)`: SHA-256 of `JSON.stringify({ schema,
/// capabilities: keys sorted })`, the reasons left out.
fn fingerprint(manifest: &Manifest) -> String {
    let mut keys: Vec<&str> = manifest.capabilities.iter().map(|(c, _)| c.key()).collect();
    // Every key is ASCII: JavaScript's default sort is byte order here.
    keys.sort_unstable();
    let mut value = object();
    value.set("schema", text(SCHEMA));
    value.set(
        "capabilities",
        JsValue::Array(keys.into_iter().map(text).collect()),
    );
    hex(&Sha256::digest(value.stringify().as_bytes()))
}

const SCHEMA: &str = "freedom-manifest/1";

/// `validateManifest(value)`, with its refusal's text.
fn validate_manifest(value: &JsValue) -> Result<Manifest, String> {
    exact_keys(
        value,
        &["schema", "name", "description", "capabilities"],
        "manifest",
    )?;
    if !matches!(value.get("schema"), Some(JsValue::String(s)) if s == SCHEMA) {
        return Err("unsupported manifest schema".into());
    }
    let name = safe_text(value.get("name"), 32)
        .filter(|name| !crate::js::trim(name).is_empty())
        .ok_or("invalid manifest name")?;
    let description = match value.get("description") {
        None => JsString::from(""),
        Some(d) => safe_text(Some(d), 160).ok_or("invalid manifest description")?,
    };
    let capabilities = value.get("capabilities").unwrap_or(&UNDEFINED);
    exact_keys(capabilities, &["swarm"], "capabilities")?;
    let swarm = capabilities.get("swarm").unwrap_or(&UNDEFINED);
    let keys = Capability::ALL.map(Capability::key);
    exact_keys(swarm, &keys, "capabilities.swarm")?;
    if props(swarm).is_empty() {
        return Err("capabilities.swarm must not be empty".into());
    }
    let mut rows = Vec::new();
    for capability in Capability::ALL {
        let Some(row) = swarm.get(capability.key()) else {
            continue;
        };
        exact_keys(row, &["why"], &format!("capability {}", capability.key()))?;
        let why = safe_text(row.get("why"), 140)
            .filter(|why| !crate::js::trim(why).is_empty())
            .ok_or_else(|| format!("invalid reason for {}", capability.key()))?;
        rows.push((capability, why));
    }
    Ok(Manifest {
        name,
        // `value.description || ''`.
        description,
        capabilities: rows,
    })
}

/// `assertExactKeys(value, allowed, label)`.
fn exact_keys(value: &JsValue, allowed: &[&str], label: &str) -> Result<(), String> {
    let JsValue::Object(props) = value else {
        return Err(format!("{label} must be an object"));
    };
    for (key, _) in props {
        if !allowed.iter().any(|a| key == *a) {
            return Err(format!("{label} contains unknown field: {}", key.as_str()));
        }
    }
    Ok(())
}

/// The text, unless `hasUnsafeText(value, max)`: not a string, more than
/// `max` code points (a lone surrogate is one), or a C0 or C1 control, a
/// bidirectional override or isolate, or a line or paragraph separator.
fn safe_text(value: Option<&JsValue>, max: usize) -> Option<JsString> {
    let Some(JsValue::String(s)) = value else {
        return None;
    };
    let mut count = 0usize;
    for decoded in char::decode_utf16(s.units()) {
        count += 1;
        let code = match decoded {
            Ok(c) => u32::from(c),
            Err(lone) => u32::from(lone.unpaired_surrogate()),
        };
        let unsafe_char = code <= 0x1f
            || (0x7f..=0x9f).contains(&code)
            || (0x202a..=0x202e).contains(&code)
            || code == 0x2028
            || code == 0x2029
            || (0x2066..=0x2069).contains(&code);
        if unsafe_char {
            return None;
        }
    }
    (count <= max).then(|| s.clone())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// `Buffer.toString('base64url')`: no padding.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_is_node_s() {
        // Node: Buffer.from([0xfb, 0xff, 0xfe, 1]).toString('base64url')
        assert_eq!(base64url(&[0xfb, 0xff, 0xfe, 1]), "-__-AQ");
        assert_eq!(base64url(&[0; 24]).len(), 32);
        assert_eq!(base64url(b"Ma"), "TWE");
    }

    #[test]
    fn manifests_as_validate_manifest_reads_them() {
        let ok = |text: &str| validate_manifest(&fc_json::parse(text).unwrap());
        let base = "{\"schema\":\"freedom-manifest/1\",\"name\":\"N\",\"capabilities\":{\"swarm\":{\"publish\":{\"why\":\"w\"}}}}";
        let manifest = ok(base).unwrap();
        assert_eq!(manifest.description, "");
        assert!(ok("[]").is_err());
        assert!(
            ok(
                "{\"schema\":\"freedom-manifest/1\",\"name\":\"N\",\"capabilities\":{\"swarm\":{}}}"
            )
            .is_err()
        );
        assert!(ok("{\"schema\":\"freedom-manifest/1\",\"name\":\" \",\"capabilities\":{\"swarm\":{\"publish\":{\"why\":\"w\"}}}}").is_err());
        assert!(ok("{\"schema\":\"freedom-manifest/1\",\"name\":\"N\",\"x\":1,\"capabilities\":{\"swarm\":{\"publish\":{\"why\":\"w\"}}}}").is_err());
        assert!(ok("{\"schema\":\"freedom-manifest/1\",\"name\":\"N\\u202e\",\"capabilities\":{\"swarm\":{\"publish\":{\"why\":\"w\"}}}}").is_err());
        // 32 code points, a lone surrogate one of them, is the most.
        let name = format!("{}\\ud800", "n".repeat(31));
        assert!(ok(&base.replace("\"N\"", &format!("\"{name}\""))).is_ok());
        let name = format!("{}\\ud800", "n".repeat(32));
        assert!(ok(&base.replace("\"N\"", &format!("\"{name}\""))).is_err());
        // A byte-order mark is dropped; bad UTF-8 refused.
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend_from_slice(base.as_bytes());
        assert!(read_manifest(&bom).is_some());
        assert!(read_manifest(&[b'"', 0xff, b'"']).is_none());
    }

    #[test]
    fn manifest_urls_as_new_url_reads_them() {
        assert_eq!(
            manifest_url("bzz://abc/index.html").as_deref(),
            Some("bzz://abc/freedom-manifest.json")
        );
        assert_eq!(
            manifest_url("BZZ://Host:8080/x").as_deref(),
            Some("bzz://Host:8080/freedom-manifest.json")
        );
        assert_eq!(manifest_url("https://abc/"), None);
        assert_eq!(manifest_url("not a url"), None);
    }

    #[test]
    fn remove_owners_turns_the_connection_off_last() {
        let mut record = fc_json::parse(
            "{\"managed\":{\"connection\":[\"publish\"],\"autoApprove.publish\":[\"publish\"],\"identity\":[\"feeds\"],\"feedGrant\":[\"feeds\",\"signing\"]},\"acknowledged\":{}}",
        )
        .unwrap();
        let ops = remove_owners(&mut record, &[Capability::Publish, Capability::Feeds]);
        let keys: Vec<(&str, bool)> = ops
            .iter()
            .map(|op| (op.projection.key(), op.enabled))
            .collect();
        assert_eq!(
            keys,
            [("autoApprove.publish", false), ("connection", false)]
        );
        assert_eq!(
            record.get("managed").unwrap().stringify(),
            "{\"feedGrant\":[\"signing\"]}"
        );
    }

    use super::super::feeds::Source;
    use std::collections::BTreeMap;

    const NOW: u64 = 1_767_225_600_123;
    const SITE: &str = "bzz://5a5a";
    const URL: &str = "bzz://5a5a/index.html";

    fn manifest(capabilities: &[&str]) -> String {
        let rows: Vec<String> = capabilities
            .iter()
            .map(|c| format!("\"{c}\":{{\"why\":\"To {c}\"}}"))
            .collect();
        format!(
            "{{\"schema\":\"freedom-manifest/1\",\"name\":\"N\",\"capabilities\":{{\"swarm\":{{{}}}}}}}",
            rows.join(",")
        )
    }

    /// A world: the grants as flags, the feed store, the files, and a
    /// write that can be made to fail.
    #[derive(Default)]
    struct TestWorld {
        connected: BTreeMap<String, (bool, Vec<Capability>)>,
        feeds: FeedStore,
        files: BTreeMap<&'static str, String>,
        saves: Vec<Save>,
        fail_saves: bool,
        effects: Vec<Effect>,
    }

    impl Reads for TestWorld {
        fn connected(&self, key: &JsString) -> bool {
            self.connected.contains_key(key.as_str())
        }
        fn messaging(&self, key: &JsString) -> bool {
            self.connected.get(key.as_str()).is_some_and(|g| g.0)
        }
        fn auto_approve(&self, key: &JsString, capability: Capability) -> bool {
            self.connected
                .get(key.as_str())
                .is_some_and(|g| g.1.contains(&capability))
        }
        fn feeds(&self) -> &FeedStore {
            &self.feeds
        }
    }

    impl World for TestWorld {
        type Error = &'static str;
        fn apply(
            &mut self,
            key: &JsString,
            effect: Effect,
        ) -> Result<(), ManifestError<&'static str>> {
            self.effects.push(effect);
            let k = key.as_str().to_owned();
            match effect {
                Effect::Connect => {
                    self.connected.insert(k, (false, Vec::new()));
                }
                Effect::Disconnect => {
                    self.connected.remove(&k);
                }
                Effect::Flag {
                    capability,
                    enabled,
                } => {
                    let grant = self.connected.entry(k).or_default();
                    grant.1.retain(|c| *c != capability);
                    if enabled {
                        grant.1.push(capability);
                    }
                }
                Effect::Messaging(on) => self.connected.entry(k).or_default().0 = on,
                Effect::FeedGrant(on) => {
                    let changed = if on {
                        self.feeds.grant_feed_access(key, Source::Manifest)
                    } else {
                        self.feeds.revoke_feed_access(key, Source::Manifest)
                    };
                    changed.map_err(|e| match e {
                        super::super::StoreError::Thrown(t) => ManifestError::Thrown(t),
                        super::super::StoreError::Full => ManifestError::Full,
                    })?;
                }
                Effect::CreateIdentity => {
                    let mut options = object();
                    options.set("activate", JsValue::Bool(true));
                    self.feeds
                        .create_app_scoped_identity(key, &options, Source::Manifest, NOW)
                        .map_err(|_| ManifestError::World("identity"))?;
                }
            }
            Ok(())
        }
        fn save(&mut self, save: &Save) -> Result<(), &'static str> {
            if self.fail_saves {
                return Err("disk full");
            }
            if save.backup
                && let Some(current) = self.files.get(FILE_NAME).cloned()
            {
                self.files.insert(BACKUP_NAME, current);
            }
            self.files.insert(FILE_NAME, save.text.clone());
            self.saves.push(save.clone());
            Ok(())
        }
    }

    fn loaded(world: &TestWorld) -> ManifestStore {
        let mut store = ManifestStore::new();
        let file = world.files.get(FILE_NAME).cloned();
        let backup = world.files.get(BACKUP_NAME).cloned();
        store
            .load(file.as_deref().map(str::as_bytes), || {
                backup.map(String::into_bytes)
            })
            .unwrap();
        store
    }

    fn site() -> JsString {
        JsString::from(SITE)
    }

    /// A check to its consent: the token.
    fn consent(
        store: &mut ManifestStore,
        world: &mut TestWorld,
        caps: &[&str],
        owner: Owner,
        seed: u8,
    ) -> String {
        let CheckStep::Fetch(fetch) = store.check(&site(), URL, true, owner, world, NOW).unwrap()
        else {
            panic!("a fetch");
        };
        let body = manifest(caps);
        let answer = store
            .check_fetched(
                fetch,
                Fetched::Answered {
                    status: 200,
                    body: body.as_bytes(),
                },
                world,
                NOW,
                || [seed; 24],
            )
            .unwrap();
        assert_eq!(
            answer.get("kind").and_then(JsValue::as_str),
            Some("consent")
        );
        answer
            .get("token")
            .and_then(JsValue::as_str)
            .unwrap()
            .to_owned()
    }

    #[test]
    fn a_store_read_from_its_backup_keeps_it_at_the_first_write() {
        let mut world = TestWorld::default();
        world.files.insert(FILE_NAME, "{".to_owned());
        world
            .files
            .insert(BACKUP_NAME, "{\"version\":1,\"records\":{}}".to_owned());
        let mut store = loaded(&world);
        store.disconnect(&site(), &mut world).unwrap();
        let backups: Vec<bool> = world.saves.iter().map(|s| s.backup).collect();
        assert_eq!(backups, [false, true]);
    }

    #[test]
    fn consents_coalesce_in_process_and_never_for_a_page() {
        let mut world = TestWorld::default();
        let mut store = loaded(&world);
        let first = consent(&mut store, &mut world, &["publish"], Owner::InProcess, 1);
        let second = consent(&mut store, &mut world, &["publish"], Owner::InProcess, 2);
        assert_eq!(first, second, "the same state shares one consent");
        let decided = store
            .decide(&first, "deny", Owner::InProcess, &mut world, NOW)
            .unwrap();
        // A decided in-process consent is replayed.
        assert_eq!(
            store
                .decide(&first, "allow", Owner::InProcess, &mut world, NOW)
                .unwrap(),
            decided
        );
        // A page's consent is its own, and spent once decided.
        let a = consent(&mut store, &mut world, &["publish"], Owner::Page, 3);
        let b = consent(&mut store, &mut world, &["publish"], Owner::Page, 4);
        assert_ne!(a, b);
        assert!(store.page_token_is_for(&a, &site(), NOW));
        assert!(!store.page_token_is_for(&a, &JsString::from("bzz://other"), NOW));
        store.release_page_token(&a);
        assert!(!store.page_token_is_for(&a, &site(), NOW));
        let err = store
            .decide(&a, "deny", Owner::Page, &mut world, NOW)
            .unwrap_err();
        assert_eq!(
            err,
            ManifestError::Thrown(Thrown::error("Manifest consent expired"))
        );
        // Past its time, too.
        let err = store
            .decide(&b, "deny", Owner::Page, &mut world, NOW + TOKEN_TTL_MS + 1)
            .unwrap_err();
        assert_eq!(
            err,
            ManifestError::Thrown(Thrown::error("Manifest consent expired"))
        );
    }

    #[test]
    fn page_consents_are_bounded() {
        let mut world = TestWorld::default();
        let mut store = loaded(&world);
        let first = consent(&mut store, &mut world, &["publish"], Owner::Page, 0);
        for seed in 1..=MAX_PAGE_TOKENS as u8 {
            consent(&mut store, &mut world, &["publish"], Owner::Page, seed);
        }
        assert_eq!(store.page_tokens.len(), MAX_PAGE_TOKENS);
        assert!(
            !store.page_token_is_for(&first, &site(), NOW),
            "the oldest went"
        );
    }

    #[test]
    fn unresolved_checks_back_off() {
        let mut world = TestWorld::default();
        let mut store = loaded(&world);
        let mut now = NOW;
        let mut retries = Vec::new();
        for _ in 0..5 {
            let CheckStep::Fetch(fetch) = store
                .check(&site(), URL, true, Owner::Page, &mut world, now)
                .unwrap()
            else {
                panic!("a fetch");
            };
            let answer = store
                .check_fetched(fetch, Fetched::Failed, &mut world, now, || [0; 24])
                .unwrap();
            let JsValue::Number(retry) = answer.get("retryAt").cloned().unwrap() else {
                panic!()
            };
            retries.push(retry as u64 - now);
            // Within the backoff: no fetch.
            let within = store
                .check(&site(), URL, true, Owner::Page, &mut world, now + 1)
                .unwrap();
            assert!(matches!(within, CheckStep::Done(_)));
            now = retry as u64;
        }
        assert_eq!(retries, [2_000, 10_000, 30_000, 60_000, 60_000]);
        assert!(world.saves.is_empty(), "nothing written");
    }

    #[test]
    fn a_journal_is_replayed_without_an_unavailable_identity_s_grants() {
        let mut world = TestWorld::default();
        let eth = "{\"version\":2,\"nextPublisherKeyIndex\":0,\"origins\":{\"bzz://5a5a\":{\"activeIdentityId\":\"e\",\"identities\":{\"e\":{\"mode\":\"ethereum-wallet\"}}}}}";
        world.feeds = FeedStore::load(Some(eth.as_bytes()), NOW, |_| false).store;
        world.files.insert(
            FILE_NAME,
            "{\"version\":1,\"records\":{},\"pending\":{\"origin\":\"bzz://5a5a\",\"record\":{\"managed\":{\"connection\":[\"feeds\"],\"feedGrant\":[\"feeds\"]},\"acknowledged\":{}},\"operations\":[{\"projection\":\"connection\",\"enabled\":true},{\"projection\":\"feedGrant\",\"enabled\":true}]}}".to_owned(),
        );
        let mut store = loaded(&world);
        let record = store.get_record(&site(), &mut world).unwrap();
        assert_eq!(world.effects, [Effect::Connect]);
        assert_eq!(
            record.get("managed").unwrap().stringify(),
            "{\"connection\":[\"feeds\"]}"
        );
        assert!(!world.files[FILE_NAME].contains("pending"));
    }

    #[test]
    fn a_failed_write_unloads_the_store() {
        let mut world = TestWorld::default();
        let mut store = loaded(&world);
        world.fail_saves = true;
        let err = store.disconnect(&site(), &mut world).unwrap_err();
        assert_eq!(err, ManifestError::World("disk full"));
        assert!(!store.is_loaded());
        assert_eq!(
            store.get_record(&site(), &mut world),
            Err(ManifestError::NotLoaded)
        );
    }

    #[test]
    fn a_write_past_the_bound_is_refused() {
        let mut world = TestWorld::default();
        let mut big = String::from("{\"version\":1,\"records\":{},\"pad\":\"");
        big.push_str(&"x".repeat(MAX_FILE_BYTES - 64));
        big.push_str("\"}");
        world.files.insert(FILE_NAME, big);
        let mut store = loaded(&world);
        let err = store.disconnect(&site(), &mut world).unwrap_err();
        assert_eq!(err, ManifestError::Full);
        assert!(!store.is_loaded());
        assert!(world.saves.is_empty());
    }

    #[test]
    fn a_user_change_detaches_the_manifest_s_claim() {
        let mut world = TestWorld::default();
        let mut store = loaded(&world);
        let token = consent(
            &mut store,
            &mut world,
            &["publish", "feeds"],
            Owner::InProcess,
            1,
        );
        store
            .decide(&token, "allow", Owner::InProcess, &mut world, NOW)
            .unwrap();
        assert!(world.feeds.has_feed_grant(&site()));
        store
            .detach_managed(&site(), Projection::FeedGrant, &mut world)
            .unwrap();
        let record = store.get_record(&site(), &mut world).unwrap();
        assert_eq!(
            record.get("detached").unwrap().stringify(),
            "{\"feedGrant\":true}"
        );
        assert!(record.get("managed").unwrap().get("feedGrant").is_none());
        assert_eq!(record.get("revision"), Some(&JsValue::Number(2.0)));
        // The connection changed by hand disconnects.
        store
            .detach_managed(&site(), Projection::Connection, &mut world)
            .unwrap();
        assert_eq!(
            store.get_record(&site(), &mut world).unwrap(),
            JsValue::Null
        );
        assert!(!world.connected(&site()));
    }

    #[test]
    fn unreadable_shapes_fall_back_to_the_backup() {
        let good = b"{\"version\":1,\"records\":{}}".to_vec();
        for bad in [
            "[]",
            "{\"records\":[]}",
            "{\"records\":{\"k\":5}}",
            "{\"records\":{\"k\":{\"acknowledged\":{\"x\":{}}}}}",
            "{\"records\":{\"k\":{\"acknowledged\":{},\"revision\":\"1\"}}}",
            "{\"records\":{\"k\":{\"acknowledged\":{},\"managed\":{\"connection\":\"x\"}}}}",
            "{\"records\":{},\"pending\":{\"origin\":\"k\",\"record\":null,\"operations\":[{\"projection\":\"nope\",\"enabled\":true}]}}",
        ] {
            let mut store = ManifestStore::new();
            store
                .load(Some(bad.as_bytes()), || Some(good.clone()))
                .unwrap();
            assert!(store.loaded_from_backup, "{bad}");
            let mut store = ManifestStore::new();
            assert_eq!(
                store.load(Some(bad.as_bytes()), || None),
                Err(Unreadable),
                "{bad}"
            );
        }
        // Missing: empty, the backup unread.
        let mut store = ManifestStore::new();
        store.load(None, || panic!("read the backup")).unwrap();
        assert_eq!(store.doc, Some(empty_doc()));
    }
}
