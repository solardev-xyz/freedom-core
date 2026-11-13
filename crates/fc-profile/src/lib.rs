//! Profiles in the core (design 0013). This step, PRF-3: the profile
//! catalog's rules, which the `freedom-cored profile …` subcommands run,
//! with a delete's checks and paths ([`delete`]) and the forget file's form
//! and bounds ([`forget`]).
//!
//! The reference is freedom-browser's `src/main/profile-catalog.js` and
//! `profile-resolver.js` (with `profile-lock.js`'s staleness rule);
//! `vectors/profiles.json`, produced from them, is the contract (AGENTS
//! rule 5). Each operation here is the reference's, step for step: the same
//! reads, the same refusals with the same messages, and the same text
//! written after each, `JSON.stringify(…, null, 2)` in JavaScript's property
//! order, so an older build reads every file the core writes, and the core
//! every file an older build wrote.
//!
//! The crate does no I/O (AGENTS rule 2): the files come in through a
//! [`Store`], the clock as the caller's `now`, and whether another profile
//! is open as the caller's answer. The catalog's write lock, the durable
//! writes and the gates are `freedom-cored`'s.
//!
//! What differs from the reference, all of it refusing where the reference
//! would act on a file it can't have meant: a catalog record, a
//! `profile.json` or a node block that isn't a JSON object where an
//! operation would change it, and a profile directory that isn't a string,
//! are [`Error::Malformed`], where the reference would throw a `TypeError`
//! or write what its spreads made of it.

mod catalog;
pub mod delete;
pub mod forget;
mod ids;
mod js;
pub mod lock;
mod nodes;
mod open;
pub mod path;

pub use catalog::{
    Error, Options, Store, StoreError, create, import, list, load_catalog, rename, reserved_ports,
    update_nodes,
};
pub use delete::{Deletion, plan_deletion, validate_deletion};
pub use forget::forget_pending;
pub use ids::{
    DEFAULT_PROFILE_ID, checkout_id, dev_port_offset, display_name_from_id, hash_path,
    sanitize_profile_id,
};
pub use nodes::{
    DEV_PORT_BASE, PACKAGED_PORT_BASE, PortBase, Ports, allocate_slot, build_node_config,
    fill_missing_node_config, managed_ports, normalize_ipfs_mode, rebase_node_config,
};
pub use open::{AUTOMATION_PROFILE_ID, OpenArgs, OpenOutcome, Opened, open};
pub use path::Style;

/// The catalog's file at the app root.
pub const PROFILE_REGISTRY_FILE: &str = "profile-registry.json";
/// Each profile's own record, in its directory.
pub const PROFILE_META_FILE: &str = "profile.json";
/// Where named profiles live, under the app root.
pub const PROFILES_DIR: &str = "Profiles";
/// The catalog write lock's target file, at the app root (proper-lockfile's
/// `file`; nothing reads it).
pub const CATALOG_LOCK_TARGET: &str = "profile-registry.write-lock-target";
/// The catalog write lock's directory, at the app root (proper-lockfile's
/// `lockfilePath`).
pub const CATALOG_LOCK_DIR: &str = "profile-registry.write.lock";
/// The profile lock's target file, in the profile's directory.
pub const PROFILE_LOCK_TARGET: &str = "profile-open";
/// The profile lock's directory, in the profile's directory.
pub const PROFILE_LOCK_DIR: &str = "profile-open.lock";

/// The forget file, at the app root.
pub const FORGET_FILE: &str = "profile-registry.json.forget";
