//! The Freedom directory's move (design 0013, 5.4b, "The move"): the names,
//! the journal's form, what each journal entry's state calls for in a
//! recovery (PRF-3's `profile migrate --finish-only`), and whether a move
//! may start (PRF-9). freedom-cored does the moving; this decides.
//!
//! - **The journal,** `freedom/.move.json`: `{ "version": 2, "entries":
//!   [<name>, …], "copied": [<name>, …] }` and nothing else, each key once
//!   and each name once in each list, `copied` within `entries` ([`Journal`];
//!   0013's amendment of 2026-11-21, MD9). `entries` lists the entries
//!   present when the move began, in the order moved, so an entry it names
//!   is somewhere: at the root, in `freedom/`, or as its cross-device copy.
//!   `copied` names the entries the move copies across devices rather than
//!   renames, each added before its copy begins (MG1): such an entry may be
//!   at both places, and its source is removed only after the marker.
//!   Version 1, `{ "version": 1, "entries": [<name>, …] }`, which PRF-3's
//!   recovery read, still parses, with nothing copied.
//! - **A name** is one of [`MOVED_ENTRIES`], the table "What moves" spells
//!   out: never a shared entry of the app root (`Profiles`, `R`, `locks`,
//!   the catalog's files), so a packaged default profile's recovery, whose
//!   directory is the app root, can't reach another profile, and never
//!   anything the shell keeps at the root (`profile.json`, the lock, set C).
//!   A journal naming anything else is corrupt.
//! - **The placeholder,** a regular file at the root's `identity`, comes
//!   after the marker (MD9): [`needs_placeholder`].
//!
//! The crate does no I/O: freedom-cored reads the directory, and asks
//! [`rollback`], [`roll_forward`] and [`plan_start`] what the state it found
//! calls for.

use fc_json::index::{Index, Kind};

/// The Freedom directory, in a profile's directory.
pub const FREEDOM_DIR: &str = "freedom";
/// The move's journal, in the Freedom directory.
pub const MOVE_JOURNAL: &str = ".move.json";
/// The move's marker, in the Freedom directory.
pub const LAYOUT_MARKER: &str = "layout.json";
/// An entry copied across devices, before its rename to its name.
pub const MOVING_SUFFIX: &str = ".moving";
/// The entry whose old place a placeholder file takes.
pub const PLACEHOLDER: &str = "identity";
/// The placeholder's text: where the data went (0013, "The move").
pub const PLACEHOLDER_TEXT: &str = "This profile's Freedom data is in freedom/. This file holds the old identity/ directory's place, so an older build of Freedom can't make a second identity here.\n";
/// The largest journal read: every name, far past what it needs.
pub const MAX_JOURNAL_BYTES: u64 = 16 * 1024;

/// What moves into `freedom/` (0013, 5.4b, "What moves"): `identity/`,
/// every set-A and set-B store at the profile's root (5.2, "Which stores"),
/// with the SQLite databases' companion files, and the nodes' data and
/// `run/`. A name the list doesn't know stays where it is.
pub const MOVED_ENTRIES: &[&str] = &[
    "identity",
    // Set A.
    "wallet-intents.jsonl",
    "safe-pending.json",
    "dapp-permissions.json",
    "swarm-permissions.json",
    "radicle-permissions.json",
    "x402-permissions.json",
    "phone-payments.json",
    "swarm-feeds.json",
    "swarm-manifest-grants.json",
    "rpc-api-keys.json",
    "payment-history.sqlite",
    "payment-history.sqlite-wal",
    "payment-history.sqlite-shm",
    "publish-history.sqlite",
    "publish-history.sqlite-wal",
    "publish-history.sqlite-shm",
    // Set B.
    "settings.json",
    "network-config.json",
    "custom-chains.json",
    "custom-tokens.json",
    "permissions.json",
    "adblock-allowlist.json",
    "external-node-decisions.json",
    "balance-cache.json",
    "chain-catalog.json",
    "swarm-browsing-credit.json",
    // The nodes' data, and antd's hand-off.
    "ant-data",
    "ipfs-data",
    "tor-data",
    "myotis",
    "bee-data",
    "run",
];

/// A profile's layout, as the reader release reads it (0013, "Readers, and
/// the downgrade"; `profile open`'s `layout`):
/// - **[`Layout::Pending`]** while a move's journal is there, before its
///   marker or after it: the entries may be in either place;
/// - **[`Layout::Freedom`]** once the marker is: the Freedom root is
///   `freedom/`;
/// - **[`Layout::Root`]** otherwise: the Freedom root is the profile's
///   directory itself.
///
/// The caller looks for the journal and the marker as `lstat` would (a
/// symlink at either name is there); it reads the layout only under the
/// profile gate, which a move holds for its whole run, so the layout can't
/// change under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    Root,
    Freedom,
    Pending,
}

impl Layout {
    /// From whether `freedom/.move.json` and `freedom/layout.json` are
    /// there.
    pub fn read(journal: bool, marker: bool) -> Layout {
        if journal {
            Layout::Pending
        } else if marker {
            Layout::Freedom
        } else {
            Layout::Root
        }
    }

    /// `profile open`'s word for it.
    pub fn word(self) -> &'static str {
        match self {
            Layout::Root => "root",
            Layout::Freedom => "freedom",
            Layout::Pending => "pending",
        }
    }

    /// The Freedom roots a delete gates the core's and freedom-ipfsd's
    /// directories in, as names below the profile's directory: the
    /// directory itself (no name) and, once a move has begun (a journal
    /// pending, or the marker there), `freedom/` too, the root's first. The
    /// root stays gated after the move: a build from before the reader
    /// release, run after a downgrade, looks for its stores at the root and
    /// starts its services there (0013, "Readers, and the downgrade").
    pub fn gated_roots(self) -> &'static [&'static [&'static str]] {
        match self {
            Layout::Root => &[&[]],
            Layout::Freedom | Layout::Pending => &[&[], &[FREEDOM_DIR]],
        }
    }
}

/// A move's journal, in form: its entries in the order moved, and those of
/// them copied across devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    entries: Vec<&'static str>,
    copied: Vec<&'static str>,
}

impl Journal {
    /// The journal a move writes first: `entries` in the order given, none
    /// copied. `None` for a name not in [`MOVED_ENTRIES`], or one named
    /// twice.
    pub fn new(entries: &[&str]) -> Option<Journal> {
        Some(Journal {
            entries: known_once(entries.iter().copied())?,
            copied: Vec::new(),
        })
    }

    /// Its entries, in the order moved.
    pub fn entries(&self) -> &[&'static str] {
        &self.entries
    }

    /// The entries copied across devices, in the order added.
    pub fn copied(&self) -> &[&'static str] {
        &self.copied
    }

    /// Whether `name` is copied across devices.
    pub fn is_copied(&self, name: &str) -> bool {
        self.copied.contains(&name)
    }

    /// The journal written again before `name`'s copy begins: `name` added
    /// to `copied`. `None` for a name not among its entries, or one already
    /// copied.
    pub fn with_copied(&self, name: &str) -> Option<Journal> {
        let name = *self.entries.iter().find(|entry| **entry == name)?;
        if self.is_copied(name) {
            return None;
        }
        let mut next = self.clone();
        next.copied.push(name);
        Some(next)
    }

    /// The text a move writes, always version 2: `{"version":2,"entries":
    /// […],"copied":[…]}`, with no white space and no newline. Every name
    /// is printable ASCII with no `"` or `\`, so none is escaped.
    pub fn text(&self) -> String {
        let list = |names: &[&str]| {
            names
                .iter()
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "{{\"version\":2,\"entries\":[{}],\"copied\":[{}]}}",
            list(&self.entries),
            list(&self.copied)
        )
    }
}

/// Each name as [`MOVED_ENTRIES`] spells it, or `None` for a name not in the
/// list, or one named twice.
fn known_once<'a>(names: impl Iterator<Item = &'a str>) -> Option<Vec<&'static str>> {
    let mut out: Vec<&'static str> = Vec::new();
    for name in names {
        let name = *MOVED_ENTRIES.iter().find(|known| **known == name)?;
        if out.contains(&name) {
            return None;
        }
        out.push(name);
    }
    Some(out)
}

/// The journal, or `None` for one out of form: not JSON, a version other
/// than 1 or 2, a key missing, another key, a key twice, `copied` in a
/// version 1 journal, a name not in [`MOVED_ENTRIES`], a name twice in
/// either list, or a copied name that isn't an entry. A version 1 journal
/// has nothing copied.
///
/// Read from the text's own members, duplicates included, not through
/// `fc_json::parse`, whose JavaScript semantics keep a duplicate key's last
/// value: `{"version":1,"entries":["identity"],"entries":[]}` would read as
/// a journal of nothing. Neither of two lists is trusted.
pub fn parse_journal(text: &str) -> Option<Journal> {
    let index = Index::new(text).ok()?;
    let journal = index.root();
    if journal.kind() != Kind::Object {
        return None;
    }
    let mut version = None;
    let mut entries = None;
    let mut copied = None;
    for (key, value) in journal.members() {
        let slot = if key.is_str("version") {
            &mut version
        } else if key.is_str("entries") {
            &mut entries
        } else if key.is_str("copied") {
            &mut copied
        } else {
            return None;
        };
        if slot.replace(value).is_some() {
            return None;
        }
    }
    let version = version?;
    if version.kind() != Kind::Number {
        return None;
    }
    let copied = match copied {
        None if version.number() == 1.0 => Vec::new(),
        Some(copied) if version.number() == 2.0 => names(copied)?,
        _ => return None,
    };
    let entries = names(entries?)?;
    if !copied.iter().all(|name| entries.contains(name)) {
        return None;
    }
    Some(Journal { entries, copied })
}

/// A list of names, each in [`MOVED_ENTRIES`] and named once.
fn names(list: fc_json::index::Value<'_, '_>) -> Option<Vec<&'static str>> {
    if list.kind() != Kind::Array {
        return None;
    }
    let mut out: Vec<&'static str> = Vec::new();
    for name in list.children() {
        let name = *MOVED_ENTRIES.iter().find(|known| name.is_str(known))?;
        if out.contains(&name) {
            return None;
        }
        out.push(name);
    }
    Some(out)
}

/// What is at a name, not following a symlink: the caller's reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    Missing,
    File,
    Dir,
    /// A symlink, or anything else that isn't a regular file or a
    /// directory: moved as itself.
    Other,
}

impl Found {
    fn present(self) -> bool {
        self != Found::Missing
    }
}

/// One entry's state: at the profile's root, in `freedom/`, and its
/// cross-device copy `freedom/<name>.moving`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryState {
    pub at_root: Found,
    pub moved: Found,
    pub moving: Found,
}

impl EntryState {
    /// In no place at all.
    fn nowhere(self) -> bool {
        !self.at_root.present() && !self.moved.present() && !self.moving.present()
    }

    /// For a copied entry: whether each copy there is of the root entry's
    /// kind, so the root's can be the source it was copied from. A copy
    /// begins as the source's kind (a directory, a file, a link) and keeps
    /// it; a source being removed keeps its kind until it is gone.
    fn copies_match_source(self) -> bool {
        [self.moved, self.moving]
            .into_iter()
            .all(|copy| !copy.present() || copy == self.at_root)
    }
}

/// What an entry's rollback does, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Steps {
    /// Remove `freedom/<name>.moving`: a copy cut short, whose source is
    /// still at the root.
    pub remove_moving: bool,
    /// Remove `freedom/<name>`: a copied entry's finished copy, whose source
    /// is still at the root.
    pub remove_moved: bool,
    /// Remove the placeholder file at the root's `identity`.
    pub remove_placeholder: bool,
    /// Rename `freedom/<name>` back to the root.
    pub rename_back: bool,
}

/// Why an entry can't be settled without a guess: the run changes nothing,
/// and the profile stays closed with a message (0013: "The core doesn't
/// guess which entries moved").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsettled {
    /// A copy cut short whose source is no longer at the root.
    MovingWithoutSource,
    /// Before the marker, a copied entry whose source is no longer at the
    /// root, or is another kind of entry than its copy. The source is
    /// removed only after the marker, so something else removed or replaced
    /// it, and nothing shows the copy is whole.
    SourceGone,
    /// A renamed entry at both places, and the root's isn't the
    /// placeholder: something made at the root since, or a cross-device
    /// copy and its source from a journal that doesn't say so (version 1).
    /// Names alone can't tell which to keep.
    AtBoth,
    /// After the marker, a copy still in progress, or the entry at the
    /// root alone.
    NotMoved,
    /// The entry in no place at all, before the marker or after it. The
    /// journal lists only entries present, and no step of the move removes
    /// every copy of one: a rename leaves one side, and a cross-device copy
    /// keeps its source past the marker. The journal is the last record that
    /// the entry existed, so it stays.
    Nowhere,
}

/// Before the marker: the entry put back at the root.
///
/// - **Renamed** (not in `copied`): `freedom/<name>` renamed back. A copy
///   cut short (a version 1 journal's) is removed while its source is at
///   the root, and the placeholder file at `identity` beside the moved
///   directory removed first.
/// - **Copied:** while its source is at the root, of each copy's kind, the
///   copies go (`freedom/<name>` and `<name>.moving`) and the source stays.
///   A source gone or replaced is [`Unsettled::SourceGone`] (or
///   [`Unsettled::MovingWithoutSource`] beside a copy cut short).
pub fn rollback(name: &str, copied: bool, state: EntryState) -> Result<Steps, Unsettled> {
    if state.nowhere() {
        return Err(Unsettled::Nowhere);
    }
    let mut steps = Steps::default();
    if state.moving.present() {
        if !state.at_root.present() {
            return Err(Unsettled::MovingWithoutSource);
        }
        steps.remove_moving = true;
    }
    if copied {
        if !state.at_root.present() || !state.copies_match_source() {
            return Err(Unsettled::SourceGone);
        }
        steps.remove_moved = state.moved.present();
        return Ok(steps);
    }
    if !state.moved.present() {
        return Ok(steps);
    }
    match state.at_root {
        Found::Missing => steps.rename_back = true,
        Found::File if name == PLACEHOLDER && state.moved == Found::Dir => {
            steps.remove_placeholder = true;
            steps.rename_back = true;
        }
        _ => return Err(Unsettled::AtBoth),
    }
    Ok(steps)
}

/// What an entry's roll-forward does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Forward {
    /// Remove what is at the root: a copied entry's source, perhaps half
    /// removed.
    pub remove_source: bool,
}

/// After the marker: the entry stays in `freedom/`, and must be there whole
/// (no copy in progress), or the run is [`Unsettled::NotMoved`].
///
/// - **Copied:** what is at the root, of the copy's kind, is its source,
///   perhaps half removed by the cleanup a crash cut short: it is removed.
///   Anything of another kind (the placeholder beside a directory, or a
///   link where a directory was) isn't the source, and stays.
/// - **Renamed:** nothing at the root is removed. An entry beside it (one
///   an older build made since) stays where it is, unmerged; 0013's
///   set-aside of such residue is the optional PRF-9d.
///
/// Once every entry's roll-forward is done, [`needs_placeholder`] says
/// whether to write the placeholder. An entry in no place at all is
/// [`Unsettled::Nowhere`].
pub fn roll_forward(copied: bool, state: EntryState) -> Result<Forward, Unsettled> {
    if state.nowhere() {
        return Err(Unsettled::Nowhere);
    }
    if state.moving.present() || !state.moved.present() {
        return Err(Unsettled::NotMoved);
    }
    Ok(Forward {
        remove_source: copied && state.at_root == state.moved,
    })
}

/// After the marker, once the roll-forward's removals are done (or after a
/// starting move's cleanup): whether the placeholder must be written, from
/// what the caller finds at the root's `identity` now. Only where nothing
/// is: the placeholder already there, or anything else at that name, stays
/// as it is, so writing it is idempotent and replaces nothing (MD9). A
/// profile that never had an `identity/` gets one too, so an older build
/// can't make an identity at the root of a moved profile.
pub fn needs_placeholder(identity_at_root: Found) -> bool {
    identity_at_root == Found::Missing
}

/// A name of [`MOVED_ENTRIES`] at the profile's root, as the caller found
/// it before a move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtRoot {
    pub found: Found,
    /// The entry is a mount point: on another device than the profile's
    /// directory, looked at without following a symlink.
    pub mount_point: bool,
}

/// The profile's `freedom/`, as the caller found it before a move, not
/// following a symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreedomDir<'a> {
    Missing,
    /// A directory, with the names in it (each lossily as UTF-8).
    Dir(&'a [String]),
    /// Anything else: a file, a symlink (to a directory too), a junction.
    Other,
}

/// What a starting move looks at (0013, "The move", the preconditions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartState<'a> {
    /// What the caller found at each name of [`MOVED_ENTRIES`] at the
    /// profile's root, looked up by name, as a reader looks it up (so by
    /// the volume's own rule for names). A name left out is missing; a name
    /// not in the list is ignored.
    pub root: &'a [(&'a str, AtRoot)],
    pub freedom: FreedomDir<'a>,
    /// A node identity journal or its staging file is pending in
    /// `identity/` (freedom-cored's `node-identity-journal.json`,
    /// `node-identity-staging.json`).
    pub node_identity_journal: bool,
}

/// Why a starting move doesn't start: the run changes nothing, ends with
/// `deferred`, and the profile opens in the old layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deferral {
    /// A node identity journal or staging file is pending: it records an
    /// absolute root, and its recovery after the move would make the root's
    /// `ant-data/` again (MG3).
    NodeIdentityJournal,
    /// `freedom/` is there and isn't a directory.
    FreedomNotDir,
    /// `freedom/` holds this name (as found), one the move writes, compared
    /// folded: an entry's, its `.moving` name, the journal or the marker.
    FreedomHolds(String),
    /// This entry is a mount point (MD6): its rename fails with `EBUSY` on
    /// Linux, and a copy's cleanup would empty the volume.
    MountPoint(&'static str),
}

impl Deferral {
    /// The reason's word, for the log.
    pub fn word(&self) -> &'static str {
        match self {
            Deferral::NodeIdentityJournal => "node_identity_journal",
            Deferral::FreedomNotDir => "freedom_not_dir",
            Deferral::FreedomHolds(_) => "freedom_holds",
            Deferral::MountPoint(_) => "mount_point",
        }
    }
}

/// Whether a starting move may start, and on which entries: those of
/// [`MOVED_ENTRIES`] present at the root, in the list's order, which the
/// journal names (none for a new profile, whose empty move writes no
/// journal: MD5). Checked in this order, the first that fails deferring:
/// a pending node identity journal; `freedom/`, which must be missing or a
/// directory holding no name the move writes; and each present entry, in
/// the list's order, which must not be a mount point.
///
/// Names in `freedom/` compare by [`crate::delete::fold`], without the
/// trailing dots and spaces Win32 drops from a name, on every OS: a fold
/// wider than a volume's only defers more.
pub fn plan_start(state: &StartState<'_>) -> Result<Vec<&'static str>, Deferral> {
    if state.node_identity_journal {
        return Err(Deferral::NodeIdentityJournal);
    }
    match state.freedom {
        FreedomDir::Missing => {}
        FreedomDir::Other => return Err(Deferral::FreedomNotDir),
        FreedomDir::Dir(names) => {
            if let Some(name) = names.iter().find(|name| written_by_the_move(name)) {
                return Err(Deferral::FreedomHolds(name.clone()));
            }
        }
    }
    let mut present = Vec::new();
    for name in MOVED_ENTRIES {
        let Some((_, at_root)) = state.root.iter().find(|(seen, _)| seen == name) else {
            continue;
        };
        if !at_root.found.present() {
            continue;
        }
        if at_root.mount_point {
            return Err(Deferral::MountPoint(name));
        }
        present.push(*name);
    }
    Ok(present)
}

/// Whether a name in `freedom/` is one the move writes there.
fn written_by_the_move(name: &str) -> bool {
    let key = crate::delete::fold(name.trim_end_matches(['.', ' ']));
    let matches = |written: &str| crate::delete::fold(written) == key;
    matches(MOVE_JOURNAL)
        || matches(LAYOUT_MARKER)
        || MOVED_ENTRIES
            .iter()
            .any(|entry| matches(entry) || matches(&format!("{entry}{MOVING_SUFFIX}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal(entries: &[&'static str], copied: &[&'static str]) -> Journal {
        Journal {
            entries: entries.to_vec(),
            copied: copied.to_vec(),
        }
    }

    #[test]
    fn the_journal_in_form_and_out() {
        assert_eq!(
            parse_journal(r#"{"version":1,"entries":["identity","ipfs-data"]}"#),
            Some(journal(&["identity", "ipfs-data"], &[]))
        );
        assert_eq!(
            parse_journal(r#"{ "entries": [], "version": 1 }"#),
            Some(journal(&[], &[]))
        );
        // Version 2: `copied` within `entries`, in any order of its own, and
        // the keys in any order.
        assert_eq!(
            parse_journal(
                r#"{"version":2,"entries":["identity","ant-data","run"],"copied":["run","ant-data"]}"#
            ),
            Some(journal(
                &["identity", "ant-data", "run"],
                &["run", "ant-data"]
            ))
        );
        assert_eq!(
            parse_journal(r#"{"copied":[],"entries":["run"],"version":2}"#),
            Some(journal(&["run"], &[]))
        );
        assert_eq!(
            parse_journal(r#"{"version":2,"entries":[],"copied":[]}"#),
            Some(journal(&[], &[]))
        );
        // The same number in another spelling is the same number.
        assert_eq!(
            parse_journal(r#"{"version":2.0,"entries":[],"copied":[]}"#),
            Some(journal(&[], &[]))
        );
        for text in [
            "",
            "not json",
            "[]",
            "null",
            r#"{"version":1}"#,
            r#"{"entries":[]}"#,
            r#"{"version":0,"entries":[]}"#,
            r#"{"version":3,"entries":[],"copied":[]}"#,
            r#"{"version":"1","entries":[]}"#,
            r#"{"version":"2","entries":[],"copied":[]}"#,
            r#"{"version":null,"entries":[],"copied":[]}"#,
            r#"{"version":1,"entries":"identity"}"#,
            r#"{"version":1,"entries":[1]}"#,
            r#"{"version":1,"entries":["identity","identity"]}"#,
            r#"{"version":1,"entries":[],"extra":true}"#,
            // Version 1 has no `copied`, even an empty one; version 2 has
            // it always.
            r#"{"version":1,"entries":[],"copied":[]}"#,
            r#"{"version":1,"entries":["run"],"copied":["run"]}"#,
            r#"{"version":2,"entries":[]}"#,
            r#"{"version":2,"entries":["run"]}"#,
            r#"{"version":2,"copied":[]}"#,
            // Version 2 out of form: another key, a list that isn't one,
            // a name not in the list, a name twice in either list, a copied
            // name that isn't an entry.
            r#"{"version":2,"entries":[],"copied":[],"extra":true}"#,
            r#"{"version":2,"entries":[],"copied":null}"#,
            r#"{"version":2,"entries":["run"],"copied":"run"}"#,
            r#"{"version":2,"entries":null,"copied":[]}"#,
            r#"{"version":2,"entries":["run"],"copied":[1]}"#,
            r#"{"version":2,"entries":["Profiles"],"copied":[]}"#,
            r#"{"version":2,"entries":["run"],"copied":["Profiles"]}"#,
            r#"{"version":2,"entries":["run","run"],"copied":[]}"#,
            r#"{"version":2,"entries":["run"],"copied":["run","run"]}"#,
            r#"{"version":2,"entries":["run"],"copied":["ant-data"]}"#,
            r#"{"version":2,"entries":[],"copied":["run"]}"#,
            r#"{"version":2,"entries":["run"],"copied":["run.moving"]}"#,
            // Shared entries of the app root, the shell's, and paths.
            r#"{"version":1,"entries":["Profiles"]}"#,
            r#"{"version":1,"entries":["R"]}"#,
            r#"{"version":1,"entries":["locks"]}"#,
            r#"{"version":1,"entries":["profile-registry.json"]}"#,
            r#"{"version":1,"entries":["profile.json"]}"#,
            r#"{"version":1,"entries":["profile-open.lock"]}"#,
            r#"{"version":1,"entries":["Local State"]}"#,
            r#"{"version":1,"entries":["freedom"]}"#,
            r#"{"version":1,"entries":["identity.moving"]}"#,
            r#"{"version":1,"entries":["../identity"]}"#,
            r#"{"version":1,"entries":["ipfs-data/freedom-ipfs"]}"#,
            r#"{"version":1,"entries":[""]}"#,
            r#"{"version":1,"entries":["Identity"]}"#,
            // A key twice, in either order: JavaScript would keep the last
            // value, but the journal's keys are exact, so neither is
            // trusted.
            r#"{"version":1,"entries":["identity"],"entries":[]}"#,
            r#"{"version":1,"entries":[],"entries":["identity"]}"#,
            r#"{"entries":[],"version":1,"entries":["identity"]}"#,
            r#"{"version":1,"entries":[],"version":1}"#,
            r#"{"version":2,"entries":[],"version":1}"#,
            r#"{"version":1,"entries":[],"version":2}"#,
            r#"{"version":1,"version":1,"entries":[]}"#,
            r#"{"version":2,"entries":["run"],"copied":[],"copied":["run"]}"#,
            r#"{"version":2,"entries":["run"],"copied":["run"],"copied":[]}"#,
            // The same key in another spelling is the same key.
            r#"{"version":1,"entries":[],"entries":["identity"]}"#,
            r#"{"version":1,"entries":[],"version":1}"#,
            r#"{"version":2,"entries":["run"],"copied":[],"copied":["run"]}"#,
        ] {
            assert_eq!(parse_journal(text), None, "{text}");
        }
        // An escaped name is the name.
        assert_eq!(
            parse_journal(r#"{"version":1,"entries":["identity"]}"#),
            Some(journal(&["identity"], &[]))
        );
        assert_eq!(
            parse_journal(r#"{"version":2,"entries":["run"],"copied":["run"]}"#),
            Some(journal(&["run"], &["run"]))
        );
    }

    #[test]
    fn the_journal_a_move_writes() {
        let first = Journal::new(&["identity", "ant-data", "run"]).unwrap();
        assert_eq!(first, journal(&["identity", "ant-data", "run"], &[]));
        assert_eq!(
            first.text(),
            r#"{"version":2,"entries":["identity","ant-data","run"],"copied":[]}"#
        );
        // Written again before each copy begins.
        let second = first.with_copied("run").unwrap();
        let third = second.with_copied("ant-data").unwrap();
        assert_eq!(
            third.text(),
            r#"{"version":2,"entries":["identity","ant-data","run"],"copied":["run","ant-data"]}"#
        );
        assert!(third.is_copied("run") && third.is_copied("ant-data"));
        assert!(!third.is_copied("identity"));
        assert_eq!(third.entries(), ["identity", "ant-data", "run"]);
        assert_eq!(third.copied(), ["run", "ant-data"]);
        for written in [&first, &second, &third] {
            assert_eq!(parse_journal(&written.text()).as_ref(), Some(written));
        }
        // Copied twice, or not an entry.
        assert_eq!(third.with_copied("run"), None);
        assert_eq!(third.with_copied("tor-data"), None);
        assert_eq!(third.with_copied("Profiles"), None);
        // Not in the list, or twice.
        assert_eq!(Journal::new(&["Profiles"]), None);
        assert_eq!(Journal::new(&["run", "run"]), None);
        assert_eq!(Journal::new(&[]), Some(journal(&[], &[])));
        // The largest journal, every entry copied, is far within the bound.
        let mut all = Journal::new(MOVED_ENTRIES).unwrap();
        for name in MOVED_ENTRIES {
            all = all.with_copied(name).unwrap();
        }
        assert!((all.text().len() as u64) < MAX_JOURNAL_BYTES / 4);
        assert_eq!(parse_journal(&all.text()), Some(all));
    }

    #[test]
    fn the_layout_as_the_reader_release_reads_it() {
        assert_eq!(Layout::read(false, false), Layout::Root);
        assert_eq!(Layout::read(false, true), Layout::Freedom);
        // A journal is pending before its marker and after it.
        assert_eq!(Layout::read(true, false), Layout::Pending);
        assert_eq!(Layout::read(true, true), Layout::Pending);
        assert_eq!(
            [Layout::Root, Layout::Freedom, Layout::Pending].map(Layout::word),
            ["root", "freedom", "pending"]
        );
        let empty: &[&str] = &[];
        assert_eq!(Layout::Root.gated_roots(), [empty]);
        for moved in [Layout::Freedom, Layout::Pending] {
            assert_eq!(moved.gated_roots(), [empty, &[FREEDOM_DIR]]);
        }
    }

    #[test]
    fn no_moved_entry_is_shared_or_the_shells() {
        for name in [
            "Profiles",
            "R",
            "locks",
            "profile.json",
            "profile-open",
            "profile-open.lock",
            "radicle-data",
            "crash-reports",
            FREEDOM_DIR,
        ] {
            assert!(!MOVED_ENTRIES.contains(&name), "{name}");
        }
        for name in MOVED_ENTRIES {
            assert!(!name.starts_with("profile-registry"), "{name}");
            assert!(!name.contains(['/', '\\']) && !name.ends_with(MOVING_SUFFIX));
            // Written into the journal unescaped.
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\'),
                "{name}"
            );
        }
        assert_eq!(
            Journal::new(MOVED_ENTRIES).map(|j| j.entries.len()),
            Some(MOVED_ENTRIES.len())
        );
    }

    fn state(at_root: Found, moved: Found, moving: Found) -> EntryState {
        EntryState {
            at_root,
            moved,
            moving,
        }
    }

    fn steps(
        remove_moving: bool,
        remove_moved: bool,
        remove_placeholder: bool,
        rename_back: bool,
    ) -> Steps {
        Steps {
            remove_moving,
            remove_moved,
            remove_placeholder,
            rename_back,
        }
    }

    const KINDS: [Found; 4] = [Found::Missing, Found::File, Found::Dir, Found::Other];

    /// Every cell of presence (at the root, in `freedom/`, as `.moving`),
    /// each present place a directory, for an entry that isn't `identity`,
    /// renamed and copied. The placeholder and the kinds follow.
    #[test]
    fn rollback_every_cell() {
        use Found::{Dir as D, Missing as M};
        use Unsettled::*;
        let ok = |s| Ok::<Steps, Unsettled>(s);
        let none = Steps::default();
        // (root, moved, moving): renamed, copied.
        let cells = [
            ((M, M, M), Err(Nowhere), Err(Nowhere)),
            // Not moved yet; a copy not begun.
            ((D, M, M), ok(none), ok(none)),
            // Renamed: back. Copied with its source gone: no guess.
            (
                (M, D, M),
                ok(steps(false, false, false, true)),
                Err(SourceGone),
            ),
            // Both places: a renamed entry's is ambiguous; a copied one's
            // copy goes, its source stays.
            ((D, D, M), Err(AtBoth), ok(steps(false, true, false, false))),
            // A copy cut short whose source is gone.
            (
                (M, M, D),
                Err(MovingWithoutSource),
                Err(MovingWithoutSource),
            ),
            // A copy cut short, its source still at the root.
            (
                (D, M, D),
                ok(steps(true, false, false, false)),
                ok(steps(true, false, false, false)),
            ),
            (
                (M, D, D),
                Err(MovingWithoutSource),
                Err(MovingWithoutSource),
            ),
            ((D, D, D), Err(AtBoth), ok(steps(true, true, false, false))),
        ];
        for ((root, moved, moving), renamed, copied) in cells {
            let s = state(root, moved, moving);
            assert_eq!(rollback("ant-data", false, s), renamed, "renamed {s:?}");
            assert_eq!(rollback("ant-data", true, s), copied, "copied {s:?}");
        }
    }

    #[test]
    fn rollback_the_placeholder_and_the_kinds() {
        use Found::*;
        // The placeholder file at `identity` beside the moved directory
        // (a version 1 journal's order): removed, and the directory back.
        assert_eq!(
            rollback("identity", false, state(File, Dir, Missing)),
            Ok(steps(false, false, true, true))
        );
        assert_eq!(
            rollback("identity", false, state(File, Dir, Dir)),
            Ok(steps(true, false, true, true))
        );
        // Only for `identity`, only a file, only beside a directory.
        for (name, s) in [
            ("settings.json", state(File, Dir, Missing)),
            ("identity", state(File, File, Missing)),
            ("identity", state(Dir, Dir, Missing)),
            ("identity", state(Other, Dir, Missing)),
            ("settings.json", state(File, File, Missing)),
        ] {
            assert_eq!(
                rollback(name, false, s),
                Err(Unsettled::AtBoth),
                "{name} {s:?}"
            );
        }
        // A copied entry is never the placeholder: the file at `identity`
        // isn't the directory copied, so the source is gone.
        assert_eq!(
            rollback("identity", true, state(File, Dir, Missing)),
            Err(Unsettled::SourceGone)
        );
        // A symlink moved as itself goes back; one copied as a link goes.
        assert_eq!(
            rollback("tor-data", false, state(Missing, Other, Missing)),
            Ok(steps(false, false, false, true))
        );
        assert_eq!(
            rollback("tor-data", true, state(Other, Other, Missing)),
            Ok(steps(false, true, false, false))
        );
        assert_eq!(
            rollback("settings.json", true, state(File, File, File)),
            Ok(steps(true, true, false, false))
        );
        // A copied entry's root replaced by another kind: not the source.
        for s in [
            state(File, Dir, Missing),
            state(Other, Dir, Missing),
            state(Dir, Other, Missing),
            state(File, Missing, Dir),
            state(Dir, Dir, File),
        ] {
            assert_eq!(
                rollback("ant-data", true, s),
                Err(Unsettled::SourceGone),
                "{s:?}"
            );
        }
    }

    /// Every kind in every place: whatever the cell, a rollback never
    /// removes an entry's last copy, never both renames back and removes,
    /// and treats a copied entry by its kinds alone.
    #[test]
    fn rollback_never_loses_the_last_copy() {
        for name in ["identity", "ant-data"] {
            for root in KINDS {
                for moved in KINDS {
                    for moving in KINDS {
                        let s = state(root, moved, moving);
                        for copied in [false, true] {
                            let Ok(steps) = rollback(name, copied, s) else {
                                continue;
                            };
                            let at_root_after = root.present() && !steps.remove_placeholder;
                            // The entry stays somewhere: at the root.
                            assert!(at_root_after || steps.rename_back, "{name} {copied} {s:?}");
                            assert!(!(steps.rename_back && steps.remove_moved), "{s:?}");
                            assert!(!steps.remove_moving || root.present(), "{s:?}");
                            assert!(!steps.remove_moved || (copied && root == moved), "{s:?}");
                            assert!(
                                !steps.remove_placeholder || (!copied && name == PLACEHOLDER),
                                "{s:?}"
                            );
                            assert_eq!(steps.remove_moving, moving.present(), "{s:?}");
                            assert!(!steps.rename_back || (!copied && moved.present()), "{s:?}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn roll_forward_every_cell() {
        use Found::{Dir as D, Missing as M};
        use Unsettled::*;
        let keep = Ok::<Forward, Unsettled>(Forward::default());
        let remove = Ok::<Forward, Unsettled>(Forward {
            remove_source: true,
        });
        // (root, moved, moving): renamed, copied.
        let cells = [
            ((M, M, M), Err(Nowhere), Err(Nowhere)),
            ((D, M, M), Err(NotMoved), Err(NotMoved)),
            ((M, D, M), keep, keep),
            // Both places: a renamed entry's root one stays (residue); a
            // copied one's is its source, perhaps half removed.
            ((D, D, M), keep, remove),
            ((M, M, D), Err(NotMoved), Err(NotMoved)),
            ((D, M, D), Err(NotMoved), Err(NotMoved)),
            ((M, D, D), Err(NotMoved), Err(NotMoved)),
            ((D, D, D), Err(NotMoved), Err(NotMoved)),
        ];
        for ((root, moved, moving), renamed, copied) in cells {
            let s = state(root, moved, moving);
            assert_eq!(roll_forward(false, s), renamed, "renamed {s:?}");
            assert_eq!(roll_forward(true, s), copied, "copied {s:?}");
        }
    }

    #[test]
    fn roll_forward_the_placeholder_and_the_kinds() {
        use Found::*;
        let keep = Ok(Forward::default());
        let remove = Ok(Forward {
            remove_source: true,
        });
        // The placeholder beside the moved directory stays, copied or not.
        assert_eq!(roll_forward(false, state(File, Dir, Missing)), keep);
        assert_eq!(roll_forward(true, state(File, Dir, Missing)), keep);
        // A copied source of the copy's kind goes, whatever the kind.
        assert_eq!(roll_forward(true, state(File, File, Missing)), remove);
        assert_eq!(roll_forward(true, state(Other, Other, Missing)), remove);
        // Another kind isn't the source: it stays.
        assert_eq!(roll_forward(true, state(Other, Dir, Missing)), keep);
        assert_eq!(roll_forward(true, state(Dir, Other, Missing)), keep);
        // A renamed entry's residue stays, whatever its kind.
        for root in KINDS {
            assert_eq!(roll_forward(false, state(root, Dir, Missing)), keep);
        }
        // A copy still in progress, of any kind, after the marker.
        for moving in [File, Dir, Other] {
            for copied in [false, true] {
                assert_eq!(
                    roll_forward(copied, state(Dir, Dir, moving)),
                    Err(Unsettled::NotMoved)
                );
            }
        }
    }

    /// Every kind in every place: a roll-forward removes only a copied
    /// entry's source of the copy's kind, and only once the copy is in
    /// place whole.
    #[test]
    fn roll_forward_removes_only_a_copied_source() {
        for root in KINDS {
            for moved in KINDS {
                for moving in KINDS {
                    let s = state(root, moved, moving);
                    for copied in [false, true] {
                        let result = roll_forward(copied, s);
                        assert_eq!(
                            result.is_ok(),
                            moved.present() && !moving.present(),
                            "{s:?}"
                        );
                        if let Ok(forward) = result {
                            assert_eq!(forward.remove_source, copied && root == moved, "{s:?}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_placeholder_only_where_nothing_is() {
        assert!(needs_placeholder(Found::Missing));
        for there in [Found::File, Found::Dir, Found::Other] {
            assert!(!needs_placeholder(there), "{there:?}");
        }
    }

    fn present(found: Found) -> AtRoot {
        AtRoot {
            found,
            mount_point: false,
        }
    }

    fn start<'a>(root: &'a [(&'a str, AtRoot)], freedom: FreedomDir<'a>) -> StartState<'a> {
        StartState {
            root,
            freedom,
            node_identity_journal: false,
        }
    }

    #[test]
    fn a_move_starts_on_the_entries_present_in_the_lists_order() {
        let root = [
            ("run", present(Found::Dir)),
            ("settings.json", present(Found::File)),
            ("identity", present(Found::Dir)),
            ("tor-data", present(Found::Other)),
            ("ipfs-data", present(Found::Missing)),
            // Not in the list: stays where it is.
            ("Cookies", present(Found::File)),
            ("radicle-data", present(Found::Dir)),
        ];
        let expected = vec!["identity", "settings.json", "tor-data", "run"];
        assert_eq!(
            plan_start(&start(&root, FreedomDir::Missing)),
            Ok(expected.clone())
        );
        // A `freedom/` holding other names: they stay.
        let other = [
            "notes.txt".to_owned(),
            ".move.json.tmp".to_owned(),
            "identity-old".to_owned(),
        ];
        assert_eq!(
            plan_start(&start(&root, FreedomDir::Dir(&other))),
            Ok(expected.clone())
        );
        assert_eq!(
            plan_start(&start(&root, FreedomDir::Dir(&[]))),
            Ok(expected)
        );
        // A new profile: an empty move.
        assert_eq!(plan_start(&start(&[], FreedomDir::Missing)), Ok(Vec::new()));
        // A mount point that is missing isn't there to defer.
        let gone = [(
            "ant-data",
            AtRoot {
                found: Found::Missing,
                mount_point: true,
            },
        )];
        assert_eq!(
            plan_start(&start(&gone, FreedomDir::Missing)),
            Ok(Vec::new())
        );
    }

    #[test]
    fn a_move_defers_on_what_it_cant_move_safely() {
        let root = [
            ("identity", present(Found::Dir)),
            (
                "ant-data",
                AtRoot {
                    found: Found::Dir,
                    mount_point: true,
                },
            ),
            (
                "ipfs-data",
                AtRoot {
                    found: Found::Dir,
                    mount_point: true,
                },
            ),
        ];
        // Mount points: the first in the list's order.
        assert_eq!(
            plan_start(&start(&root, FreedomDir::Missing)),
            Err(Deferral::MountPoint("ant-data"))
        );
        // `freedom/` before the mount points, and the node journal first.
        assert_eq!(
            plan_start(&start(&root, FreedomDir::Other)),
            Err(Deferral::FreedomNotDir)
        );
        let mut journal = start(&root, FreedomDir::Other);
        journal.node_identity_journal = true;
        assert_eq!(plan_start(&journal), Err(Deferral::NodeIdentityJournal));
        let plain = [("identity", present(Found::Dir))];
        let mut journal = start(&plain, FreedomDir::Missing);
        journal.node_identity_journal = true;
        assert_eq!(plan_start(&journal), Err(Deferral::NodeIdentityJournal));
        // A name in `freedom/` the move writes, folded as a volume might
        // fold it, and without Win32's trailing dots and spaces.
        for name in [
            "identity",
            "IDENTITY",
            "settings.json",
            "ſettings.json",
            "custom-to\u{212a}ens.json",
            "identity.moving",
            "Identity.Moving",
            "ant-data.moving",
            ".move.json",
            "layout.json",
            "Layout.JSON",
            "identity.",
            "identity ",
            "run. . ",
        ] {
            let names = ["notes.txt".to_owned(), name.to_owned()];
            assert_eq!(
                plan_start(&start(&plain, FreedomDir::Dir(&names))),
                Err(Deferral::FreedomHolds(name.to_owned())),
                "{name}"
            );
        }
        assert_eq!(
            [
                Deferral::NodeIdentityJournal,
                Deferral::FreedomNotDir,
                Deferral::FreedomHolds(String::new()),
                Deferral::MountPoint("run"),
            ]
            .map(|d| d.word()),
            [
                "node_identity_journal",
                "freedom_not_dir",
                "freedom_holds",
                "mount_point"
            ]
        );
    }
}
