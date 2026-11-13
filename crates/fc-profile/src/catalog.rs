//! The catalog's operations: `loadCatalog`, `ensureProfile`, `createProfile`,
//! `renameProfile`, `importProfile`, `updateProfileNodeConfig`,
//! `getReservedManagedPorts` and `listProfileSummaries`, as
//! `profile-catalog.js` has them, over a [`Store`].
//!
//! The caller holds the catalog's write lock around each operation that
//! writes, as the reference's `withCatalogWriteLock` does.

use fc_json::JsValue;

use crate::ids::{DEFAULT_PROFILE_ID, display_name_from_id, sanitize_profile_id};
use crate::js::{self, is_integer, nullish, object, or, prop, spread, string};
use crate::nodes::{
    allocate_slot, build_node_config, fill_missing_node_config, managed_ports, rebase_node_config,
    record_ports, used_slots,
};
use crate::path::Style;
use crate::{PROFILE_META_FILE, PROFILE_REGISTRY_FILE, PROFILES_DIR};

/// Where the catalog's files are read and written. Paths are text, as the
/// reference's are: what the catalog records.
pub trait Store {
    /// The text of the file at `path`, `None` when nothing is there
    /// (`existsSync`, then `readFileSync`).
    fn read(&mut self, path: &str) -> Result<Option<String>, StoreError>;
    /// Whether a directory is at `path`, following a link there
    /// (`existsSync(p) && statSync(p).isDirectory()`).
    fn is_dir(&mut self, path: &str) -> Result<bool, StoreError>;
    /// The names of the directories in `path`, not following links, in name
    /// order (libuv's `scandir`); none when nothing is at `path`.
    fn list_dirs(&mut self, path: &str) -> Result<Vec<String>, StoreError>;
    /// Makes the directory `path` and any missing parent (`ensureDir`).
    fn ensure_dir(&mut self, path: &str) -> Result<(), StoreError>;
    /// Replaces the file at `path` with `text`, its directory made first
    /// (`writeJsonAtomic`).
    fn write(&mut self, path: &str, text: &str) -> Result<(), StoreError>;
    /// `path.resolve(path)`.
    fn resolve(&self, path: &str) -> String;
}

/// A store's failure, at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    pub path: String,
    pub message: String,
}

/// Why an operation changed nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A request the reference refuses, with the message it throws.
    Refused(String),
    /// A catalog or `profile.json` that isn't JSON (the reference's
    /// `SyntaxError`).
    Unreadable { path: String },
    /// A catalog that isn't version 1, with its `profiles` an array.
    Unsupported { path: String },
    /// A file the core won't act on: a catalog record, a `profile.json` or
    /// a node block that isn't an object where an operation reads into or
    /// changes it, or a profile directory that isn't text (the reference's
    /// `TypeError`, or a spread of what it can't have meant).
    Malformed { path: String },
    /// The store failed.
    Store(StoreError),
}

impl Error {
    /// The reference's message, for a refusal or an unsupported catalog.
    pub fn message(&self) -> Option<String> {
        match self {
            Error::Refused(message) => Some(message.clone()),
            Error::Unsupported { path } => Some(format!("Unsupported profile catalog: {path}")),
            _ => None,
        }
    }
}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Error::Store(error)
    }
}

/// How the caller runs: a dev or a packaged build, the dev checkout's hash
/// (its ports' offset), the `default` profile's directory where it isn't
/// `Profiles/default` (the packaged app root), and the path style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub dev: bool,
    pub checkout_hash: Option<String>,
    pub default_profile_dir: Option<String>,
    pub style: Style,
}

impl Options {
    pub(crate) fn hash(&self) -> Option<&str> {
        self.checkout_hash.as_deref()
    }
}

pub(crate) fn catalog_path(app_root: &str, style: Style) -> String {
    style.join(&[app_root, PROFILE_REGISTRY_FILE])
}

fn meta_path(dir: &str, style: Style) -> String {
    style.join(&[dir, PROFILE_META_FILE])
}

/// The JSON at `path`, `None` when nothing is there.
fn read_json(store: &mut dyn Store, path: &str) -> Result<Option<JsValue>, Error> {
    match store.read(path)? {
        None => Ok(None),
        Some(text) => fc_json::parse(&text)
            .map(Some)
            .map_err(|_| Error::Unreadable {
                path: path.to_owned(),
            }),
    }
}

/// `loadCatalog(appRoot)`: `{ version: 1, profiles: [] }` when there is
/// none; refused unless it is version 1 with an array of profiles.
pub fn load_catalog(store: &mut dyn Store, app_root: &str, style: Style) -> Result<JsValue, Error> {
    let path = catalog_path(app_root, style);
    let Some(parsed) = read_json(store, &path)? else {
        let mut empty = object();
        empty.set("version", JsValue::Number(1.0));
        empty.set("profiles", JsValue::Array(Vec::new()));
        return Ok(empty);
    };
    let supported = matches!(parsed.get("version"), Some(JsValue::Number(n)) if *n == 1.0)
        && matches!(parsed.get("profiles"), Some(JsValue::Array(_)));
    if supported {
        Ok(parsed)
    } else {
        Err(Error::Unsupported { path })
    }
}

/// A loaded catalog whose every record is an object: what the operations
/// act on.
fn load_records(store: &mut dyn Store, app_root: &str, style: Style) -> Result<JsValue, Error> {
    let catalog = load_catalog(store, app_root, style)?;
    if profiles(&catalog)
        .iter()
        .any(|record| !matches!(record, JsValue::Object(_)))
    {
        return Err(Error::Malformed {
            path: catalog_path(app_root, style),
        });
    }
    Ok(catalog)
}

pub(crate) fn profiles(catalog: &JsValue) -> &[JsValue] {
    catalog
        .get("profiles")
        .and_then(JsValue::as_array)
        .unwrap_or(&[])
}

/// The records of a catalog [`load_catalog`] accepted, to change.
fn profiles_mut<'a>(catalog: &'a mut JsValue, path: &str) -> Result<&'a mut Vec<JsValue>, Error> {
    match catalog.get_mut("profiles") {
        Some(JsValue::Array(items)) => Ok(items),
        _ => Err(Error::Malformed {
            path: path.to_owned(),
        }),
    }
}

/// `findProfile(catalog, id)`'s index.
pub(crate) fn find_index(profiles: &[JsValue], id: &str) -> Option<usize> {
    profiles
        .iter()
        .position(|record| js::is_str(&prop(record, "id"), id))
}

/// A record's `dir`, which must be text.
pub(crate) fn record_dir(record: &JsValue, catalog: &str) -> Result<String, Error> {
    match record.get("dir") {
        Some(JsValue::String(dir)) => Ok(dir.as_str().to_owned()),
        _ => Err(Error::Malformed {
            path: catalog.to_owned(),
        }),
    }
}

/// `readProfileMetadata(dir)`: the parsed `profile.json`, `null` when there
/// is none.
fn read_metadata(store: &mut dyn Store, dir: &str, style: Style) -> Result<JsValue, Error> {
    Ok(read_json(store, &meta_path(dir, style))?.unwrap_or(JsValue::Null))
}

fn write_metadata(
    store: &mut dyn Store,
    dir: &str,
    metadata: &JsValue,
    style: Style,
) -> Result<(), Error> {
    store.ensure_dir(dir)?;
    store.write(&meta_path(dir, style), &metadata.stringify_pretty())?;
    Ok(())
}

fn save_catalog(
    store: &mut dyn Store,
    app_root: &str,
    catalog: &JsValue,
    style: Style,
) -> Result<(), Error> {
    store.write(&catalog_path(app_root, style), &catalog.stringify_pretty())?;
    Ok(())
}

/// `getProfileDir(appRoot, id, options)`.
fn profile_dir(app_root: &str, id: &str, opts: &Options) -> String {
    match &opts.default_profile_dir {
        Some(dir) if id == DEFAULT_PROFILE_ID && !dir.is_empty() => dir.clone(),
        _ => opts.style.join(&[app_root, PROFILES_DIR, id]),
    }
}

fn record_of(entries: Vec<(&str, JsValue)>) -> JsValue {
    let mut out = object();
    for (key, value) in entries {
        out.set(key, value);
    }
    out
}

/// `createProfileRecord(appRoot, id, options)`.
fn new_record(
    app_root: &str,
    profiles: &[JsValue],
    id: &str,
    display_name: Option<&str>,
    opts: &Options,
    now: &str,
) -> JsValue {
    let slot = allocate_slot(profiles, id);
    let ports = managed_ports(slot, opts.dev, opts.hash());
    let display_name = match display_name {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => display_name_from_id(id),
    };
    record_of(vec![
        ("id", string(id)),
        ("displayName", string(&display_name)),
        ("dir", string(&profile_dir(app_root, id, opts))),
        ("slot", JsValue::Number(slot)),
        ("createdAt", string(now)),
        ("lastOpenedAt", string(now)),
        ("nodes", build_node_config(&ports)),
    ])
}

/// `createProfileMetadata(record)`.
fn new_metadata(record: &JsValue) -> JsValue {
    record_of(vec![
        ("version", JsValue::Number(1.0)),
        ("id", prop(record, "id")),
        ("displayName", prop(record, "displayName")),
        ("createdAt", prop(record, "createdAt")),
        ("lastOpenedAt", prop(record, "lastOpenedAt")),
        ("slot", prop(record, "slot")),
        ("nodes", prop(record, "nodes")),
    ])
}

/// `createRecordFromExistingProfile(appRoot, id, dir, catalog, options)`.
fn record_from_existing(
    store: &mut dyn Store,
    profiles: &[JsValue],
    id: &str,
    dir: &str,
    opts: &Options,
    now: &str,
) -> Result<JsValue, Error> {
    let existing = or(read_metadata(store, dir, opts.style)?, object);
    let used = used_slots(profiles);
    let metadata_slot = match prop(&existing, "slot") {
        JsValue::Number(n) if is_integer(&JsValue::Number(n)) => Some(n),
        _ => None,
    };
    let slot = match metadata_slot {
        Some(slot) if !used.contains(&slot) => slot,
        _ => allocate_slot(profiles, id),
    };
    let ports = managed_ports(slot, opts.dev, opts.hash());
    let display_name = or(prop(&existing, "displayName"), || {
        string(&display_name_from_id(id))
    });
    Ok(record_of(vec![
        ("id", string(id)),
        ("displayName", display_name),
        ("dir", string(dir)),
        ("slot", JsValue::Number(slot)),
        (
            "createdAt",
            or(prop(&existing, "createdAt"), || string(now)),
        ),
        (
            "lastOpenedAt",
            or(prop(&existing, "lastOpenedAt"), || string(now)),
        ),
        (
            "nodes",
            rebase_node_config(&or(prop(&existing, "nodes"), object), &ports),
        ),
    ]))
}

/// `{ ...a, ...b }`.
fn spread_two(a: &JsValue, b: &JsValue) -> JsValue {
    let mut out = object();
    spread(&mut out, a);
    spread(&mut out, b);
    out
}

/// What `ensureProfile` returns.
pub(crate) struct Ensured {
    pub catalog_path: String,
    pub record: JsValue,
    pub metadata: JsValue,
}

/// `ensureProfile(appRoot, id, options)`: the profile's record, registered
/// (adopting a directory with a `profile.json`, or a new one) if the catalog
/// lacks it, with any missing node field filled in, and, with
/// `mark_opened`, `lastOpenedAt` set to `now`. Each file is written only if
/// it changed.
pub(crate) fn ensure_profile(
    store: &mut dyn Store,
    app_root: &str,
    opts: &Options,
    id: &str,
    mark_opened: bool,
    now: &str,
) -> Result<Ensured, Error> {
    let style = opts.style;
    let path = catalog_path(app_root, style);
    let mut catalog = load_records(store, app_root, style)?;
    let mut catalog_changed = false;
    let mut adopted = false;
    let index = match find_index(profiles(&catalog), id) {
        Some(index) => {
            let record = &mut profiles_mut(&mut catalog, &path)?[index];
            let current = or(prop(record, "nodes"), object);
            let nodes =
                fill_missing_node_config(&current, &record_ports(record, opts.dev, opts.hash()));
            if nodes.stringify() != current.stringify() {
                record.set("nodes", nodes);
                catalog_changed = true;
            }
            index
        }
        None => {
            let dir = profile_dir(app_root, id, opts);
            let dir_exists = store.is_dir(&dir)?;
            let existing = if dir_exists {
                read_metadata(store, &dir, style)?
            } else {
                JsValue::Null
            };
            let record = if existing.truthy() {
                adopted = true;
                record_from_existing(store, profiles(&catalog), id, &dir, opts, now)?
            } else if dir_exists && id != DEFAULT_PROFILE_ID {
                return Err(Error::Refused(format!(
                    "Profile directory exists but is not registered: {id}. Import it from the profile manager before launching it."
                )));
            } else {
                new_record(app_root, profiles(&catalog), id, None, opts, now)
            };
            let records = profiles_mut(&mut catalog, &path)?;
            records.push(record);
            catalog_changed = true;
            records.len() - 1
        }
    };

    let dir = record_dir(&profiles(&catalog)[index], &path)?;
    store.ensure_dir(&dir)?;
    let mut metadata_changed = false;
    let mut metadata = if adopted {
        metadata_changed = true;
        new_metadata(&profiles(&catalog)[index])
    } else {
        let meta = meta_path(&dir, style);
        match read_json(store, &meta)? {
            Some(metadata @ JsValue::Object(_)) => {
                let record = &profiles(&catalog)[index];
                let merged = spread_two(
                    &or(prop(record, "nodes"), object),
                    &or(prop(&metadata, "nodes"), object),
                );
                let normalized =
                    fill_missing_node_config(&merged, &record_ports(record, opts.dev, opts.hash()));
                if normalized.stringify() != or(prop(&metadata, "nodes"), object).stringify() {
                    let mut changed = spread_two(&metadata, &JsValue::Null);
                    changed.set("nodes", normalized);
                    metadata_changed = true;
                    changed
                } else {
                    metadata
                }
            }
            Some(_) => return Err(Error::Malformed { path: meta }),
            None => {
                metadata_changed = true;
                new_metadata(&profiles(&catalog)[index])
            }
        }
    };

    if mark_opened {
        let record = &mut profiles_mut(&mut catalog, &path)?[index];
        if !js::is_str(&prop(record, "lastOpenedAt"), now) {
            record.set("lastOpenedAt", string(now));
            catalog_changed = true;
        }
        if !js::is_str(&prop(&metadata, "lastOpenedAt"), now) {
            let mut changed = spread_two(&metadata, &JsValue::Null);
            changed.set("lastOpenedAt", string(now));
            metadata = changed;
            metadata_changed = true;
        }
    }

    if catalog_changed {
        save_catalog(store, app_root, &catalog, style)?;
    }
    if metadata_changed {
        write_metadata(store, &dir, &metadata, style)?;
    }
    let record = profiles(&catalog)[index].clone();
    Ok(Ensured {
        catalog_path: path,
        record,
        metadata,
    })
}

fn result(catalog: JsValue, record: JsValue, metadata: JsValue) -> JsValue {
    record_of(vec![
        ("catalog", catalog),
        ("record", record),
        ("metadata", metadata),
    ])
}

/// `createProfile(appRoot, { id, displayName }, options)` →
/// `{ catalog, record, metadata }`.
pub fn create(
    store: &mut dyn Store,
    app_root: &str,
    opts: &Options,
    display_name: &str,
    id: Option<&str>,
    now: &str,
) -> Result<JsValue, Error> {
    let style = opts.style;
    let display_name = js::trim(display_name);
    let id = sanitize_profile_id(id.filter(|id| !id.is_empty()).unwrap_or(display_name))?;
    if display_name.is_empty() {
        return Err(Error::Refused("Profile display name is required".into()));
    }
    let mut catalog = load_records(store, app_root, style)?;
    if find_index(profiles(&catalog), &id).is_some() {
        return Err(Error::Refused(format!("Profile already exists: {id}")));
    }
    let record = new_record(
        app_root,
        profiles(&catalog),
        &id,
        Some(display_name),
        opts,
        now,
    );
    profiles_mut(&mut catalog, &catalog_path(app_root, style))?.push(record.clone());
    save_catalog(store, app_root, &catalog, style)?;
    let metadata = new_metadata(&record);
    write_metadata(store, &record_dir(&record, "")?, &metadata, style)?;
    Ok(result(catalog, record, metadata))
}

/// `renameProfile(appRoot, id, displayName)` → `{ catalog, record,
/// metadata }`.
pub fn rename(
    store: &mut dyn Store,
    app_root: &str,
    style: Style,
    id: &str,
    display_name: &str,
) -> Result<JsValue, Error> {
    let id = sanitize_profile_id(id)?;
    let display_name = js::trim(display_name);
    if display_name.is_empty() {
        return Err(Error::Refused("Profile display name is required".into()));
    }
    let path = catalog_path(app_root, style);
    let mut catalog = load_records(store, app_root, style)?;
    let Some(index) = find_index(profiles(&catalog), &id) else {
        return Err(Error::Refused(format!("Profile not found: {id}")));
    };
    profiles_mut(&mut catalog, &path)?[index].set("displayName", string(display_name));
    save_catalog(store, app_root, &catalog, style)?;
    let record = profiles(&catalog)[index].clone();
    let dir = record_dir(&record, &path)?;
    let existing = or(read_metadata(store, &dir, style)?, || new_metadata(&record));
    let mut metadata = spread_two(&existing, &JsValue::Null);
    metadata.set("id", prop(&record, "id"));
    metadata.set("displayName", string(display_name));
    write_metadata(store, &dir, &metadata, style)?;
    Ok(result(catalog, record, metadata))
}

/// `importProfile(appRoot, id, options)`: registers `Profiles/<id>`, a
/// directory the catalog doesn't list, from its `profile.json` →
/// `{ catalog, record, metadata }`.
pub fn import(
    store: &mut dyn Store,
    app_root: &str,
    opts: &Options,
    id: &str,
    now: &str,
) -> Result<JsValue, Error> {
    let style = opts.style;
    let id = sanitize_profile_id(id)?;
    if id == DEFAULT_PROFILE_ID {
        return Err(Error::Refused(
            "The default profile is already registered".into(),
        ));
    }
    let mut catalog = load_records(store, app_root, style)?;
    if find_index(profiles(&catalog), &id).is_some() {
        return Err(Error::Refused(format!("Profile already exists: {id}")));
    }
    let root = style.join(&[app_root, PROFILES_DIR]);
    let dir = style.join(&[&root, &id]);
    if !store.is_dir(&dir)? {
        return Err(Error::Refused(format!("Profile directory not found: {id}")));
    }
    if !is_inside(store, style, &root, &dir) {
        return Err(Error::Refused(
            "Refusing to import a profile outside the profiles directory".into(),
        ));
    }
    let record = record_from_existing(store, profiles(&catalog), &id, &dir, opts, now)?;
    profiles_mut(&mut catalog, &catalog_path(app_root, style))?.push(record.clone());
    save_catalog(store, app_root, &catalog, style)?;
    let metadata = new_metadata(&record);
    write_metadata(store, &dir, &metadata, style)?;
    Ok(result(catalog, record, metadata))
}

/// `isPathInside(parent, child)`: `child` strictly below `parent`, both
/// resolved.
fn is_inside(store: &dyn Store, style: Style, parent: &str, child: &str) -> bool {
    let parent = style.normalize(&store.resolve(parent));
    let child = style.normalize(&store.resolve(child));
    let sep = if style == Style::Windows { '\\' } else { '/' };
    let prefix = if parent.ends_with(sep) {
        parent
    } else {
        format!("{parent}{sep}")
    };
    child.len() > prefix.len() && child.starts_with(&prefix)
}

/// The node blocks `updateProfileNodeConfig` takes.
const NODE_PROTOCOLS: [&str; 5] = ["bee", "ipfs", "myotis", "radicle", "tor"];

/// `obj.nodes[protocol] = …` as `updateProfileNodeConfig` does it, on a
/// record or a metadata object: `nodes` made if missing, and the block
/// replaced (Myotis) or merged with `updates`.
fn set_node_block(
    target: &mut JsValue,
    protocol: &str,
    updates: &JsValue,
    replace: bool,
    path: &str,
) -> Result<(), Error> {
    let malformed = || Error::Malformed {
        path: path.to_owned(),
    };
    if !prop(target, "nodes").truthy() {
        target.set("nodes", object());
    }
    let nodes = target.get_mut("nodes").ok_or_else(malformed)?;
    if !matches!(nodes, JsValue::Object(_)) {
        return Err(malformed());
    }
    let block = if replace {
        updates.clone()
    } else {
        spread_two(&or(prop(nodes, protocol), object), updates)
    };
    nodes.set(protocol, block);
    Ok(())
}

/// `updateProfileNodeConfig({ appRoot, userDataDir, id, metadata },
/// protocol, updates)` → `{ catalog, record, metadata }`: the protocol's
/// node block, in the catalog's record (if it lists `id`) and in the
/// profile's `profile.json` (from `fallback`, main's copy, if there is
/// none).
#[allow(clippy::too_many_arguments)]
pub fn update_nodes(
    store: &mut dyn Store,
    app_root: &str,
    style: Style,
    id: &str,
    user_data_dir: &str,
    fallback: &JsValue,
    protocol: &str,
    updates: &JsValue,
) -> Result<JsValue, Error> {
    if !NODE_PROTOCOLS.contains(&protocol) {
        return Err(Error::Refused(format!(
            "Unsupported profile node protocol: {protocol}"
        )));
    }
    let native = match protocol {
        "ipfs" => Some("freedom-ipfs"),
        "myotis" => Some("myotis-native"),
        _ => None,
    };
    let force_native_managed = native.is_some() && protocol != "ipfs";
    let normalized = match native {
        Some(backend) if force_native_managed => {
            let mode = if nullish(updates) {
                JsValue::Undefined
            } else {
                prop(updates, "mode")
            };
            record_of(vec![
                (
                    "mode",
                    string(if js::is_str(&mode, "disabled") {
                        "disabled"
                    } else {
                        "managed"
                    }),
                ),
                ("backend", string(backend)),
            ])
        }
        Some(backend) => {
            let mut out = spread_two(updates, &JsValue::Null);
            out.set("backend", string(backend));
            out
        }
        None => updates.clone(),
    };

    let path = catalog_path(app_root, style);
    let mut catalog = load_records(store, app_root, style)?;
    let index = find_index(profiles(&catalog), id);
    if let Some(index) = index {
        let record = &mut profiles_mut(&mut catalog, &path)?[index];
        set_node_block(record, protocol, &normalized, force_native_managed, &path)?;
        save_catalog(store, app_root, &catalog, style)?;
    }

    let meta = meta_path(user_data_dir, style);
    let mut metadata = match read_json(store, &meta)? {
        Some(metadata @ JsValue::Object(_)) => metadata,
        Some(_) => return Err(Error::Malformed { path: meta }),
        None => spread_two(fallback, &JsValue::Null),
    };
    set_node_block(
        &mut metadata,
        protocol,
        &normalized,
        force_native_managed,
        &meta,
    )?;
    write_metadata(store, user_data_dir, &metadata, style)?;
    let record = match index {
        Some(index) => profiles(&catalog)[index].clone(),
        None => JsValue::Null,
    };
    Ok(result(catalog, record, metadata))
}

/// `getReservedManagedPorts(appRoot, { dev, checkoutHash,
/// excludeProfileId })`: every other profile's Bee API, Bee P2P and Tor
/// SOCKS port, once each, in the order first met.
pub fn reserved_ports(
    store: &mut dyn Store,
    app_root: &str,
    opts: &Options,
    exclude: Option<&str>,
) -> Result<Vec<f64>, Error> {
    let style = opts.style;
    let path = catalog_path(app_root, style);
    let catalog = load_records(store, app_root, style)?;
    let mut ports: Vec<f64> = Vec::new();
    for record in profiles(&catalog) {
        if let Some(exclude) = exclude.filter(|e| !e.is_empty())
            && js::is_str(&prop(record, "id"), exclude)
        {
            continue;
        }
        let metadata = or(
            read_metadata(store, &record_dir(record, &path)?, style)?,
            object,
        );
        let merged = spread_two(
            &or(prop(record, "nodes"), object),
            &or(prop(&metadata, "nodes"), object),
        );
        let nodes = fill_missing_node_config(&merged, &record_ports(record, opts.dev, opts.hash()));
        for (block, key) in [("bee", "apiPort"), ("bee", "p2pPort"), ("tor", "socksPort")] {
            if let JsValue::Number(port) = prop(&prop(&nodes, block), key)
                && is_integer(&JsValue::Number(port))
                && port > 0.0
                && !ports.contains(&port)
            {
                ports.push(port);
            }
        }
    }
    Ok(ports)
}

/// `listProfileSummaries(appRoot, { activeProfileId })`: the catalog's
/// profiles, then the directories under `Profiles/` it doesn't list whose
/// name is a canonical id it doesn't hold.
pub fn list(
    store: &mut dyn Store,
    app_root: &str,
    style: Style,
    active: Option<&str>,
) -> Result<JsValue, Error> {
    let path = catalog_path(app_root, style);
    let catalog = load_records(store, app_root, style)?;
    let is_active = |id: &JsValue| match active {
        Some(active) => js::is_str(id, active),
        None => matches!(id, JsValue::Undefined),
    };
    let mut summaries = Vec::new();
    for record in profiles(&catalog) {
        let metadata = or(
            read_metadata(store, &record_dir(record, &path)?, style)?,
            || new_metadata(record),
        );
        let record_id = prop(record, "id");
        let mut display_name = or(prop(&metadata, "displayName"), || {
            prop(record, "displayName")
        });
        if !display_name.truthy() {
            // `displayNameFromId(record.id)`, which throws for an id that
            // isn't text.
            let JsValue::String(id) = &record_id else {
                return Err(Error::Malformed { path });
            };
            display_name = string(&display_name_from_id(id));
        }
        let slot = if is_integer(&prop(&metadata, "slot")) {
            prop(&metadata, "slot")
        } else {
            prop(record, "slot")
        };
        summaries.push(record_of(vec![
            ("id", or(prop(&metadata, "id"), || record_id.clone())),
            ("displayName", display_name),
            ("slot", slot),
            (
                "createdAt",
                or(prop(&metadata, "createdAt"), || {
                    or(prop(record, "createdAt"), || JsValue::Null)
                }),
            ),
            (
                "lastOpenedAt",
                or(prop(&metadata, "lastOpenedAt"), || {
                    or(prop(record, "lastOpenedAt"), || JsValue::Null)
                }),
            ),
            (
                "nodes",
                or(prop(&metadata, "nodes"), || {
                    or(prop(record, "nodes"), || JsValue::Null)
                }),
            ),
            ("isActive", JsValue::Bool(is_active(&record_id))),
            ("isUnregistered", JsValue::Bool(false)),
        ]));
    }

    let mut registered_dirs = Vec::new();
    for record in profiles(&catalog) {
        registered_dirs.push(style.normalize(&store.resolve(&record_dir(record, &path)?)));
    }
    let root = style.join(&[app_root, PROFILES_DIR]);
    for name in store.list_dirs(&root)? {
        let dir = style.join(&[&root, &name]);
        if registered_dirs.contains(&style.normalize(&store.resolve(&dir))) {
            continue;
        }
        let Ok(id) = sanitize_profile_id(&name) else {
            continue;
        };
        if id != name || find_index(profiles(&catalog), &id).is_some() {
            continue;
        }
        let metadata = or(read_metadata(store, &dir, style)?, object);
        let slot = if is_integer(&prop(&metadata, "slot")) {
            prop(&metadata, "slot")
        } else {
            JsValue::Null
        };
        summaries.push(record_of(vec![
            ("id", string(&id)),
            (
                "displayName",
                or(prop(&metadata, "displayName"), || {
                    string(&display_name_from_id(&id))
                }),
            ),
            ("slot", slot),
            (
                "createdAt",
                or(prop(&metadata, "createdAt"), || JsValue::Null),
            ),
            (
                "lastOpenedAt",
                or(prop(&metadata, "lastOpenedAt"), || JsValue::Null),
            ),
            ("nodes", or(prop(&metadata, "nodes"), || JsValue::Null)),
            ("isActive", JsValue::Bool(active == Some(id.as_str()))),
            ("isUnregistered", JsValue::Bool(true)),
        ]));
    }
    Ok(JsValue::Array(summaries))
}
