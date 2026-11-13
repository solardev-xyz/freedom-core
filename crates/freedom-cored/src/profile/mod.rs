//! The profile subcommands (design 0013, 5.1, step PRF-3): one-shot runs on
//! main's arguments, never methods of `serve`.
//!
//! ```text
//! freedom-cored profile open --app-root <dir> --lock-dir <dir>
//!     [--dev [--checkout-hash <hex8>]] [--default-profile-dir <dir>]
//!     [--profile <id>] [--switch <id>] [--env-profile <id>] [--runtime]
//! freedom-cored profile list --app-root <dir> [--active <id>]
//! freedom-cored profile create --app-root <dir> [--dev [--checkout-hash <hex8>]]
//!     --display-name <name> [--id <id>]
//! freedom-cored profile rename --app-root <dir> --id <id> --display-name <name>
//! freedom-cored profile import --app-root <dir> [--dev [--checkout-hash <hex8>]] --id <id>
//! freedom-cored profile update-nodes --app-root <dir> --id <id> --user-data-dir <dir>
//!     --protocol <bee|ipfs|myotis|radicle|tor> --updates <json> --metadata <json>
//! freedom-cored profile reserved-ports --app-root <dir> [--dev [--checkout-hash <hex8>]]
//!     [--exclude <id>]
//! freedom-cored profile status --lock-dir <dir> [--dev] --user-data-dir <dir>...
//! freedom-cored profile delete --app-root <dir> --lock-dir <dir> --id <id>
//!     --confirm-display-name <name> [--dev [--checkout-hash <hex8>]]
//! freedom-cored profile forget-list --app-root <dir>
//! freedom-cored profile forget-done --app-root <dir> --item <32 hex>...
//! freedom-cored profile migrate --profile-dir <dir> --lock-dir <dir> [--dev] --finish-only
//! freedom-cored hold-profile --user-data-dir <dir> --lock-dir <dir> [--app-root <dir> --id <id>]
//! ```
//!
//! **Results** are one JSON line on stdout: the reference's result for each
//! catalog operation (`{ catalog, record, metadata }`, the summaries, the
//! ports), `profile open`'s object, `status`'s list, and `delete`'s and the
//! forget file's (`delete.rs`, `forget.rs`).
//!
//! **Exits:** 0 with the result; 65 for a request the reference refuses,
//! with `{ "error": "refused", "message": <its message> }` on stdout; 74 for
//! storage (an unreadable, unsupported or malformed catalog or
//! `profile.json`, a network filesystem, a file that isn't the user's, a
//! lost lock, a symlink below the app root), with `{ "error": <kind> }` on
//! stdout and the kind logged on stderr; 75 when the catalog's write lock
//! stays held, or `hold-profile`'s gate is another's; 77 when confinement
//! refuses the process (`confine.rs`); 64 for bad arguments. `migrate`'s
//! are its own (`migrate.rs`).
//!
//! **Confinement:** each run confines itself before it reads the catalog or
//! a profile's files, with read-write on what it writes, no network and no
//! child process (`confine.rs`, design 0010). `delete` confines itself once
//! its gates are taken, after its plan.
//!
//! **The catalog's write lock** is taken by each subcommand that writes,
//! for its whole run, as the reference's `withCatalogWriteLock` (5 retries,
//! 50 to 250 ms apart), and refreshed from a thread of its own (`delete`,
//! `forget-list` and `forget-done` included). The reads,
//! `list` and `reserved-ports`, take none, as the reference's don't.

mod confine;
mod delete;
mod forget;
mod lock;
mod migrate;
mod remove;
mod store;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fc_json::JsValue;
use fc_profile::{Error, OpenArgs, OpenOutcome, Options, Style};
use fc_service::gate::{CONTENTION_RETRY, GateError, PROFILE_NAMESPACE};

use crate::exit::Exit;
use crate::log;
use confine::Grant;
use lock::Lock;
use store::DiskStore;

const USAGE: &str = "usage: freedom-cored profile <open|list|create|rename|import|update-nodes|reserved-ports|status|delete|forget-list|forget-done|migrate> … | freedom-cored hold-profile --user-data-dir <dir> --lock-dir <dir> [--app-root <dir> --id <id>]";

/// The flags that take no value.
const SWITCHES: [&str; 3] = ["--dev", "--runtime", "--finish-only"];

/// A subcommand's flags: each `--name value`, and the bare switches.
struct Flags {
    values: Vec<(String, String)>,
    switches: Vec<String>,
}

impl Flags {
    /// Parses `args`, every one text; `allowed` names the flags this
    /// subcommand takes.
    fn parse(args: impl Iterator<Item = OsString>, allowed: &[&str]) -> Result<Flags, ()> {
        Flags::parse_some(args, allowed).ok_or(())
    }

    fn parse_some(args: impl Iterator<Item = OsString>, allowed: &[&str]) -> Option<Flags> {
        let mut flags = Flags {
            values: Vec::new(),
            switches: Vec::new(),
        };
        let mut args = args;
        while let Some(flag) = args.next() {
            let flag = flag.into_string().ok()?;
            if !allowed.contains(&flag.as_str()) {
                return None;
            }
            if SWITCHES.contains(&flag.as_str()) {
                flags.switches.push(flag);
            } else {
                let value = args.next()?.into_string().ok()?;
                flags.values.push((flag, value));
            }
        }
        Some(flags)
    }

    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    /// A flag given at most once.
    fn one(&self, name: &str) -> Result<Option<&str>, ()> {
        let mut found = self.values.iter().filter(|(flag, _)| flag == name);
        let first = found.next().map(|(_, value)| value.as_str());
        if found.next().is_some() {
            return Err(());
        }
        Ok(first)
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(flag, _)| flag == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// A flag given exactly once.
    fn required(&self, name: &str) -> Result<&str, ()> {
        self.one(name)?.ok_or(())
    }

    /// An absolute path, given exactly once.
    fn path(&self, name: &str) -> Result<&str, ()> {
        let path = self.required(name)?;
        if Style::native().is_absolute(path) {
            Ok(path)
        } else {
            Err(())
        }
    }

    /// The build's options: `--dev`, and its checkout's 8 hex digits.
    fn options(&self) -> Result<Options, ()> {
        let checkout_hash = self.one("--checkout-hash")?;
        if let Some(hash) = checkout_hash
            && !(hash.len() == 8 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err(());
        }
        Ok(Options {
            dev: self.has("--dev"),
            checkout_hash: checkout_hash.map(str::to_owned),
            default_profile_dir: None,
            style: Style::native(),
        })
    }
}

/// Runs `profile <sub> …` or `hold-profile …`; `args` follow the binary's
/// name. `entry` is how the process's entry went (fc-service's
/// `clean_entry`, run before anything else).
pub fn run(mut args: impl Iterator<Item = OsString>, entry: &fc_service::confine::Entry) -> Exit {
    confine::log_entry(entry);
    let command = args.next().and_then(|c| c.into_string().ok());
    let result = match command.as_deref() {
        Some("hold-profile") => hold_profile(args),
        Some("profile") => {
            let sub = args.next().and_then(|c| c.into_string().ok());
            match sub.as_deref() {
                Some("open") => open(args),
                Some("status") => status(args),
                Some("delete") => delete::run(args),
                Some(sub @ ("forget-list" | "forget-done")) => forget::run(sub, args),
                Some("migrate") => migrate::run(args),
                Some(
                    sub @ ("list" | "create" | "rename" | "import" | "update-nodes"
                    | "reserved-ports"),
                ) => catalog(sub, args),
                _ => Err(()),
            }
        }
        _ => Err(()),
    };
    result.unwrap_or_else(|()| {
        log::error(USAGE, serde_json::json!({}));
        Exit::Usage
    })
}

fn print(value: &JsValue) -> Exit {
    let mut stdout = std::io::stdout().lock();
    let mut line = value.stringify();
    line.push('\n');
    match stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => Exit::Ok,
        Err(_) => Exit::Internal,
    }
}

fn object(entries: Vec<(&str, JsValue)>) -> JsValue {
    let mut out = JsValue::Object(Vec::new());
    for (key, value) in entries {
        out.set(key, value);
    }
    out
}

/// A refusal: its message on stdout, exit 65.
fn refused(message: &str) -> Exit {
    let exit = print(&object(vec![
        ("error", JsValue::string("refused")),
        ("message", JsValue::string(message)),
    ]));
    if exit == Exit::Ok {
        Exit::Refused
    } else {
        exit
    }
}

/// A storage failure of `kind`: on stdout and stderr, exit 74.
fn storage(kind: &str, detail: &str) -> Exit {
    log::error(
        "profile storage refused",
        serde_json::json!({ "kind": kind, "detail": detail }),
    );
    let _ = print(&object(vec![("error", JsValue::string(kind))]));
    Exit::Storage
}

/// The catalog's write lock still held by another (exit 75).
fn busy() -> Exit {
    log::error(
        "the profile catalog's write lock is held",
        serde_json::json!({}),
    );
    let _ = print(&object(vec![("error", JsValue::string("busy"))]));
    Exit::LockHeld
}

/// An operation's failure, as an exit.
fn failed(error: &Error) -> Exit {
    match error {
        Error::Refused(message) => refused(message),
        Error::Unsupported { .. } => storage("unsupported", "the catalog isn't version 1"),
        Error::Unreadable { path } => storage("unreadable", file_name(path)),
        Error::Malformed { path } => storage("malformed", file_name(path)),
        Error::Store(e) if e.message == store::LOCK_LOST => {
            storage("lock_lost", "the catalog's write lock was taken over")
        }
        Error::Store(e) if e.message == store::SYMLINK => storage(
            "symlink",
            "a symlink, or another file that isn't a directory, below the app root",
        ),
        Error::Store(e) => storage("io", &e.message),
    }
}

/// A path's last component, for a log line.
fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn now_iso() -> String {
    let ms = u64::try_from(lock::now_ms()).unwrap_or(0);
    fc_vault::format::iso_timestamp(ms).unwrap_or_else(|_| "1970-01-01T00:00:00.000Z".into())
}

/// The app root, made if missing, on storage the core accepts.
fn prepare_app_root(app_root: &Path) -> Result<(), Exit> {
    if let Err(e) = store::make_dirs(app_root) {
        return Err(storage("io", &e.kind().to_string()));
    }
    match crate::storage::qualify(app_root) {
        crate::storage::Qualification::Local => Ok(()),
        crate::storage::Qualification::Network(fs) => Err(storage("network_filesystem", &fs)),
        crate::storage::Qualification::Unknown(reason) => Err(storage("unqualified", &reason)),
    }
}

/// Takes and keeps the catalog's write lock, and clears the temp files a
/// killed writer left.
fn catalog_lock(app_root: &Path) -> Result<Lock, Exit> {
    let lock = take_catalog_lock(app_root)?;
    keep(&lock)?;
    Ok(lock)
}

/// [`catalog_lock`] without the refresher: [`keep`] starts it, once the run
/// is confined.
fn take_catalog_lock(app_root: &Path) -> Result<Lock, Exit> {
    let lock = match Lock::catalog(app_root, &now_iso()) {
        Ok(lock) => lock,
        Err(lock::LockError::Held) => return Err(busy()),
        Err(lock::LockError::Io(e)) => return Err(storage("io", &e.to_string())),
    };
    if let Err(e) = store::remove_catalog_temps(app_root) {
        log::warn(
            "cannot remove the catalog's leftover temp files",
            serde_json::json!({ "error": e.kind().to_string() }),
        );
    }
    Ok(lock)
}

/// Starts the lock's refresher, after confinement.
fn keep(lock: &Lock) -> Result<(), Exit> {
    match lock.keep() {
        Ok(()) => {
            crate::testhooks::profile_hold();
            Ok(())
        }
        Err(lock::LockError::Held) => Err(busy()),
        Err(lock::LockError::Io(e)) => Err(storage("io", &e.kind().to_string())),
    }
}

/// Confines the run to `grant`, then takes and keeps the catalog's write
/// lock: a writing subcommand without gates.
fn confined_catalog_lock(app_root: &Path, grant: Grant) -> Result<Lock, Exit> {
    confine::confine(grant)?;
    catalog_lock(app_root)
}

/// `dir`, when it lies outside `app_root`: a directory main names that the
/// app root's grant doesn't cover.
fn outside(app_root: &Path, dir: &Path) -> Option<PathBuf> {
    let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_owned());
    let (root, dir) = (canonical(app_root), canonical(dir));
    (!dir.starts_with(&root)).then_some(dir)
}

/// Whether a profile reads open: its lock fresh, or its profile gate held
/// (design 0013, "What 'open' means"). A gate that can't be asked counts as
/// held.
struct Openness {
    lock_fresh: bool,
    gate_held: bool,
}

impl Openness {
    /// `gates` is whether the lock directory was there before the run
    /// confined itself: without it no gate is held, and nothing is asked
    /// (confined, a path outside the grant may not even read as missing).
    fn of(user_data_dir: &Path, lock_dir: &Path, dev: bool, gates: bool) -> Openness {
        let (stale_ms, _) = fc_profile::lock::profile_lock_timing(dev);
        let lock_fresh = lock::is_fresh(
            &user_data_dir.join(fc_profile::PROFILE_LOCK_TARGET),
            &user_data_dir.join(fc_profile::PROFILE_LOCK_DIR),
            stale_ms,
        );
        if !gates {
            return Openness {
                lock_fresh,
                gate_held: false,
            };
        }
        let gate_held = match fc_service::gate::probe(user_data_dir, lock_dir, PROFILE_NAMESPACE) {
            Ok(held) => held,
            Err(e) => {
                log::warn(
                    "cannot ask a profile's gate; it counts as held",
                    serde_json::json!({ "error": e.to_string() }),
                );
                true
            }
        };
        Openness {
            lock_fresh,
            gate_held,
        }
    }

    fn open(&self) -> bool {
        self.lock_fresh || self.gate_held
    }
}

/// `layout`: `pending` while a move's journal is there, `freedom` once its
/// marker is, `root` otherwise (design 0013, "The move").
fn layout(user_data_dir: &Path) -> &'static str {
    let freedom = user_data_dir.join("freedom");
    if std::fs::symlink_metadata(freedom.join(".move.json")).is_ok() {
        "pending"
    } else if std::fs::symlink_metadata(freedom.join("layout.json")).is_ok() {
        "freedom"
    } else {
        "root"
    }
}

fn open(args: impl Iterator<Item = OsString>) -> Result<Exit, ()> {
    let flags = Flags::parse(
        args,
        &[
            "--app-root",
            "--lock-dir",
            "--dev",
            "--checkout-hash",
            "--default-profile-dir",
            "--profile",
            "--switch",
            "--env-profile",
            "--runtime",
        ],
    )?;
    let app_root = flags.path("--app-root")?;
    let lock_dir = PathBuf::from(flags.path("--lock-dir")?);
    let mut opts = flags.options()?;
    opts.default_profile_dir = flags.one("--default-profile-dir")?.map(str::to_owned);
    let args = OpenArgs {
        profile: flags.one("--profile")?.map(str::to_owned),
        switch: flags.one("--switch")?.map(str::to_owned),
        env_profile: flags.one("--env-profile")?.map(str::to_owned),
        runtime: flags.has("--runtime"),
    };
    Ok(open_profile(app_root, &lock_dir, &opts, &args))
}

fn open_profile(app_root: &str, lock_dir: &Path, opts: &Options, args: &OpenArgs) -> Exit {
    let root = Path::new(app_root);
    if let Err(exit) = prepare_app_root(root) {
        return exit;
    }
    // The app root, the gates' probes in the lock directory, and a default
    // profile directory main names outside the app root.
    let mut grant = Grant::locking().read_write(root).read_only(lock_dir);
    if let Some(dir) = opts
        .default_profile_dir
        .as_deref()
        .filter(|dir| !dir.is_empty())
        .and_then(|dir| outside(root, Path::new(dir)))
    {
        grant = grant.read_write(&dir);
    }
    let now = now_iso();
    let gates = lock_dir.is_dir();
    let lock = match confined_catalog_lock(root, grant) {
        Ok(lock) => lock,
        Err(exit) => return exit,
    };
    let commit = || lock.held();
    let mut store = match DiskStore::open(app_root, &commit) {
        Ok(store) => store,
        Err(e) => return storage("io", &e.kind().to_string()),
    };
    let dev = opts.dev;
    let mut is_open =
        |_id: &str, dir: &str| Openness::of(Path::new(dir), lock_dir, dev, gates).open();
    let outcome = fc_profile::open(&mut store, app_root, opts, args, &now, &mut is_open);
    let forget = forget_pending(&mut store, app_root);
    drop(lock);
    let opened = match outcome {
        Ok(OpenOutcome::Opened(opened)) => opened,
        Ok(OpenOutcome::SwitchRefused(message)) => {
            return print(&object(vec![
                ("outcome", JsValue::string("switch_refused")),
                ("message", JsValue::string(&message)),
            ]));
        }
        Err(error) => return failed(&error),
    };
    let dir = Path::new(&opened.user_data_dir);
    let openness = Openness::of(dir, lock_dir, dev, gates);
    let mut out = object(vec![
        ("outcome", JsValue::string("opened")),
        ("id", opened.id.clone()),
        ("display_name", opened.display_name.clone()),
        ("user_data_dir", JsValue::string(&opened.user_data_dir)),
        (
            "slot",
            opened
                .metadata
                .get("slot")
                .cloned()
                .unwrap_or(JsValue::Null),
        ),
        (
            "nodes",
            opened
                .metadata
                .get("nodes")
                .cloned()
                .unwrap_or(JsValue::Null),
        ),
    ]);
    if opened.switch_only {
        out.set("switch_only", JsValue::Bool(true));
    }
    out.set("lock_fresh", JsValue::Bool(openness.lock_fresh));
    out.set("gate_held", JsValue::Bool(openness.gate_held));
    out.set("layout", JsValue::string(layout(dir)));
    #[allow(clippy::cast_precision_loss)]
    out.set("forget_pending", JsValue::Number(forget as f64));
    out.set("catalog_path", JsValue::string(&opened.catalog_path));
    out.set("metadata", opened.metadata);
    print(&out)
}

/// `forget_pending`: the forget file's items; one it can't read counts.
fn forget_pending(store: &mut DiskStore<'_>, app_root: &str) -> u64 {
    use fc_profile::Store as _;
    let path = Style::native().join(&[app_root, fc_profile::FORGET_FILE]);
    match store.read(&path) {
        Ok(text) => fc_profile::forget_pending(text.as_deref(), false),
        Err(_) => fc_profile::forget_pending(None, true),
    }
}

fn status(args: impl Iterator<Item = OsString>) -> Result<Exit, ()> {
    let flags = Flags::parse(args, &["--lock-dir", "--dev", "--user-data-dir"])?;
    let lock_dir = PathBuf::from(flags.path("--lock-dir")?);
    let dirs = flags.all("--user-data-dir");
    if dirs.is_empty() || dirs.iter().any(|d| !Style::native().is_absolute(d)) {
        return Err(());
    }
    let dev = flags.has("--dev");
    // Each profile's lock and the gates' probes, read only. A directory
    // that isn't there before confinement holds no gate.
    let mut grant = Grant::none().read_only(&lock_dir);
    let gates = lock_dir.is_dir();
    let mut present = Vec::with_capacity(dirs.len());
    for dir in &dirs {
        grant = grant.read_only(Path::new(dir));
        present.push(Path::new(dir).is_dir());
    }
    if let Err(exit) = confine::confine(grant) {
        return Ok(exit);
    }
    let answers = dirs
        .iter()
        .zip(present)
        .map(|(dir, present)| {
            let openness = Openness::of(Path::new(dir), &lock_dir, dev, gates && present);
            object(vec![
                ("user_data_dir", JsValue::string(*dir)),
                ("open", JsValue::Bool(openness.open())),
                ("lock_fresh", JsValue::Bool(openness.lock_fresh)),
                ("gate_held", JsValue::Bool(openness.gate_held)),
            ])
        })
        .collect();
    Ok(print(&JsValue::Array(answers)))
}

/// A catalog operation, run on the store with the run's `now`.
type Operation = Box<dyn FnOnce(&mut DiskStore<'_>, &str) -> Result<JsValue, Error>>;

fn catalog(sub: &str, args: impl Iterator<Item = OsString>) -> Result<Exit, ()> {
    let allowed: &[&str] = match sub {
        "list" => &["--app-root", "--active"],
        "create" => &[
            "--app-root",
            "--dev",
            "--checkout-hash",
            "--display-name",
            "--id",
        ],
        "rename" => &["--app-root", "--id", "--display-name"],
        "import" => &["--app-root", "--dev", "--checkout-hash", "--id"],
        "update-nodes" => &[
            "--app-root",
            "--id",
            "--user-data-dir",
            "--protocol",
            "--updates",
            "--metadata",
        ],
        _ => &["--app-root", "--dev", "--checkout-hash", "--exclude"],
    };
    let flags = Flags::parse(args, allowed)?;
    let app_root = flags.path("--app-root")?.to_owned();
    let opts = flags.options()?;
    let style = opts.style;
    let writes = !matches!(sub, "list" | "reserved-ports");
    // `update-nodes` writes `profile.json` in the directory main names,
    // which may lie outside the app root.
    let extra = match sub {
        "update-nodes" => flags
            .path("--user-data-dir")
            .ok()
            .and_then(|dir| outside(Path::new(&app_root), Path::new(dir))),
        _ => None,
    };
    // Every argument checked before anything is touched.
    let operation: Operation = match sub {
        "list" => {
            let active = flags.one("--active")?.map(str::to_owned);
            let root = app_root.clone();
            Box::new(move |store, _| fc_profile::list(store, &root, style, active.as_deref()))
        }
        "create" => {
            let display_name = flags.required("--display-name")?.to_owned();
            let id = flags.one("--id")?.map(str::to_owned);
            let (opts, root) = (opts.clone(), app_root.clone());
            Box::new(move |store, now| {
                fc_profile::create(store, &root, &opts, &display_name, id.as_deref(), now)
            })
        }
        "rename" => {
            let id = flags.required("--id")?.to_owned();
            let display_name = flags.required("--display-name")?.to_owned();
            let root = app_root.clone();
            Box::new(move |store, _| fc_profile::rename(store, &root, style, &id, &display_name))
        }
        "import" => {
            let id = flags.required("--id")?.to_owned();
            let (opts, root) = (opts.clone(), app_root.clone());
            Box::new(move |store, now| fc_profile::import(store, &root, &opts, &id, now))
        }
        "update-nodes" => {
            let id = flags.required("--id")?.to_owned();
            let user_data_dir = flags.path("--user-data-dir")?.to_owned();
            let protocol = flags.required("--protocol")?.to_owned();
            let updates = fc_json::parse(flags.required("--updates")?).map_err(|_| ())?;
            let metadata = fc_json::parse(flags.required("--metadata")?).map_err(|_| ())?;
            let root = app_root.clone();
            Box::new(move |store, _| {
                fc_profile::update_nodes(
                    store,
                    &root,
                    style,
                    &id,
                    &user_data_dir,
                    &metadata,
                    &protocol,
                    &updates,
                )
            })
        }
        _ => {
            let exclude = flags.one("--exclude")?.map(str::to_owned);
            let (opts, root) = (opts.clone(), app_root.clone());
            Box::new(move |store, _| {
                fc_profile::reserved_ports(store, &root, &opts, exclude.as_deref())
                    .map(|ports| JsValue::Array(ports.into_iter().map(JsValue::Number).collect()))
            })
        }
    };
    Ok(run_catalog(&app_root, writes, extra.as_deref(), operation))
}

fn run_catalog(app_root: &str, writes: bool, extra: Option<&Path>, operation: Operation) -> Exit {
    let root = Path::new(app_root);
    let now = now_iso();
    if !writes {
        // The reads take no lock, and change nothing.
        if let Err(exit) = confine::confine(Grant::none().read_only(root)) {
            return exit;
        }
        let commit = || false;
        let mut store = match DiskStore::open(app_root, &commit) {
            Ok(store) => store,
            Err(e) => return storage("io", &e.kind().to_string()),
        };
        return match operation(&mut store, &now) {
            Ok(value) => print(&value),
            Err(error) => failed(&error),
        };
    }
    if let Err(exit) = prepare_app_root(root) {
        return exit;
    }
    let mut grant = Grant::locking().read_write(root);
    if let Some(dir) = extra {
        grant = grant.read_write(dir);
    }
    let lock = match confined_catalog_lock(root, grant) {
        Ok(lock) => lock,
        Err(exit) => return exit,
    };
    let commit = || lock.held();
    let mut store = match DiskStore::open(app_root, &commit) {
        Ok(store) => store,
        Err(e) => return storage("io", &e.kind().to_string()),
    };
    let result = operation(&mut store, &now);
    let released = lock.release();
    match result {
        Ok(value) => {
            if !released {
                log::warn(
                    "the catalog's write lock was taken over after the change",
                    serde_json::json!({}),
                );
            }
            print(&value)
        }
        Err(error) => failed(&error),
    }
}

/// `hold-profile`: takes the profile gate, checks a catalog profile is still
/// listed at its directory, says `locked`, and holds the gate until stdin
/// closes (design 0013, "The lock").
fn hold_profile(args: impl Iterator<Item = OsString>) -> Result<Exit, ()> {
    let flags = Flags::parse(
        args,
        &["--user-data-dir", "--lock-dir", "--app-root", "--id"],
    )?;
    let user_data_dir = PathBuf::from(flags.path("--user-data-dir")?);
    let lock_dir = PathBuf::from(flags.path("--lock-dir")?);
    let listed = match (flags.one("--app-root")?, flags.one("--id")?) {
        (Some(app_root), Some(id)) if Style::native().is_absolute(app_root) => {
            Some((app_root.to_owned(), id.to_owned()))
        }
        (None, None) => None,
        _ => return Err(()),
    };
    Ok(hold(&user_data_dir, &lock_dir, listed))
}

fn hold(user_data_dir: &Path, lock_dir: &Path, listed: Option<(String, String)>) -> Exit {
    let gate = match fc_service::gate::acquire_profile(user_data_dir, lock_dir, CONTENTION_RETRY) {
        Ok(gate) => gate,
        Err(e) => {
            log::error(
                "cannot take the profile gate",
                serde_json::json!({ "error": e.to_string() }),
            );
            return match e {
                GateError::Held => Exit::LockHeld,
                _ => Exit::Storage,
            };
        }
    };
    if let Some((app_root, id)) = listed {
        match still_listed(&app_root, &id, &gate.data_dir) {
            Ok(true) => {}
            Ok(false) => {
                return refused(&format!(
                    "Profile {id} is no longer in the catalog at this directory"
                ));
            }
            Err(error) => return failed(&error),
        }
    }
    // From here, stdin, stdout and the gate alone: no file, no network, no
    // process.
    if let Err(exit) = confine::confine(Grant::none().descriptors(gate.descriptors())) {
        return exit;
    }
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(b"locked\n")
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return Exit::Internal;
    }
    let mut sink = [0u8; 4096];
    let mut stdin = std::io::stdin().lock();
    loop {
        match stdin.read(&mut sink) {
            Ok(0) => return Exit::Ok,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Exit::Internal,
        }
    }
}

/// Whether the catalog lists `id` at the directory `canonical` (the gate's).
fn still_listed(app_root: &str, id: &str, canonical: &Path) -> Result<bool, Error> {
    let commit = || false;
    let mut store = DiskStore::open(app_root, &commit).map_err(|e| {
        Error::Store(fc_profile::StoreError {
            path: app_root.to_owned(),
            message: e.kind().to_string(),
        })
    })?;
    let catalog = fc_profile::load_catalog(&mut store, app_root, Style::native())?;
    let records = catalog
        .get("profiles")
        .and_then(JsValue::as_array)
        .unwrap_or(&[]);
    Ok(records.iter().any(|record| {
        matches!(record.get("id"), Some(JsValue::String(s)) if s == id)
            && matches!(record.get("dir"), Some(JsValue::String(dir))
                if std::fs::canonicalize(dir.as_str()).is_ok_and(|d| d == canonical))
    }))
}
