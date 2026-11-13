//! The Freedom directory's move, as far as its recovery needs it (design
//! 0013, 5.4b, "The move"; PRF-3's `profile migrate --finish-only`): the
//! names, the journal's form, and what each journal entry's state calls for.
//! The move itself, which writes the journal, is PRF-9's, and PRF-9 defines
//! the journal's entries; until then this takes the narrowest reading:
//!
//! - **The journal,** `freedom/.move.json`: `{ "version": 1, "entries":
//!   [<name>, …] }` and nothing else, each key once and each name once,
//!   in the order moved. The journal lists the entries present ("The
//!   move", step 2), so an entry it names is somewhere: at the root, in
//!   `freedom/`, or as its cross-device copy.
//! - **A name** is one of [`MOVED_ENTRIES`], the table "What moves" spells
//!   out: never a shared entry of the app root (`Profiles`, `R`, `locks`,
//!   the catalog's files), so a packaged default profile's recovery, whose
//!   directory is the app root, can't reach another profile, and never
//!   anything the shell keeps at the root (`profile.json`, the lock, set C).
//!   A journal naming anything else is corrupt.
//!
//! The crate does no I/O: freedom-cored reads the directory, and asks
//! [`rollback`] or [`roll_forward`] what each entry's state calls for.

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

    /// The Freedom roots a reader may find the profile's Freedom-owned
    /// entries in, as names below the profile's directory: the directory
    /// itself (no name), `freedom/`, or, while a journal is pending, both,
    /// the root's first.
    pub fn freedom_roots(self) -> &'static [&'static [&'static str]] {
        match self {
            Layout::Root => &[&[]],
            Layout::Freedom => &[&[FREEDOM_DIR]],
            Layout::Pending => &[&[], &[FREEDOM_DIR]],
        }
    }
}

/// The journal's entries, or `None` for a journal out of form: not JSON,
/// another version, another key, a key twice, a name not in
/// [`MOVED_ENTRIES`], or one named twice.
///
/// Read from the text's own members, duplicates included, not through
/// `fc_json::parse`, whose JavaScript semantics keep a duplicate key's last
/// value: `{"version":1,"entries":["identity"],"entries":[]}` would read as
/// a journal of nothing. Neither of two lists is trusted.
pub fn parse_journal(text: &str) -> Option<Vec<String>> {
    let index = Index::new(text).ok()?;
    let journal = index.root();
    if journal.kind() != Kind::Object {
        return None;
    }
    let mut version = None;
    let mut names = None;
    for (key, value) in journal.members() {
        let slot = if key.is_str("version") {
            &mut version
        } else if key.is_str("entries") {
            &mut names
        } else {
            return None;
        };
        if slot.replace(value).is_some() {
            return None;
        }
    }
    let version = version?;
    if version.kind() != Kind::Number || version.number() != 1.0 {
        return None;
    }
    let names = names?;
    if names.kind() != Kind::Array {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for name in names.children() {
        let name = MOVED_ENTRIES.iter().find(|known| name.is_str(known))?;
        if out.iter().any(|seen| seen == name) {
            return None;
        }
        out.push((*name).to_owned());
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
}

/// What an entry's recovery does, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Steps {
    /// Remove `freedom/<name>.moving`: a copy cut short, whose source is
    /// still at the root.
    pub remove_moving: bool,
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
    /// The entry at both places, and the root's isn't the placeholder: a
    /// cross-device copy and its source, or something made at the root
    /// since. Names alone can't tell which to keep.
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
pub fn rollback(name: &str, state: EntryState) -> Result<Steps, Unsettled> {
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

/// After the marker: the entry stays in `freedom/`; nothing at the root is
/// removed. A root entry beside a moved one (a cross-device copy's source,
/// or one an older build made since) is left for PRF-9's set-aside, which
/// moves such entries, unmerged, and deletes nothing; the placeholder
/// stays. An entry in no place at all is [`Unsettled::Nowhere`].
pub fn roll_forward(state: EntryState) -> Result<(), Unsettled> {
    if state.nowhere() {
        return Err(Unsettled::Nowhere);
    }
    if state.moving.present() || !state.moved.present() {
        return Err(Unsettled::NotMoved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_journal_in_form_and_out() {
        assert_eq!(
            parse_journal(r#"{"version":1,"entries":["identity","ipfs-data"]}"#),
            Some(vec!["identity".to_owned(), "ipfs-data".to_owned()])
        );
        assert_eq!(
            parse_journal(r#"{ "entries": [], "version": 1 }"#),
            Some(Vec::new())
        );
        for text in [
            "",
            "not json",
            "[]",
            r#"{"version":1}"#,
            r#"{"entries":[]}"#,
            r#"{"version":2,"entries":[]}"#,
            r#"{"version":"1","entries":[]}"#,
            r#"{"version":1,"entries":"identity"}"#,
            r#"{"version":1,"entries":[1]}"#,
            r#"{"version":1,"entries":["identity","identity"]}"#,
            r#"{"version":1,"entries":[],"extra":true}"#,
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
            // The same key in another spelling is the same key.
            r#"{"version":1,"entries":[],"entri\u0065s":["identity"]}"#,
            r#"{"vers\u0069on":1,"entries":[],"version":1}"#,
        ] {
            assert_eq!(parse_journal(text), None, "{text}");
        }
        // An escaped name is the name.
        assert_eq!(
            parse_journal(r#"{"version":1,"entries":["\u0069dentity"]}"#),
            Some(vec!["identity".to_owned()])
        );
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
        assert_eq!(Layout::Root.freedom_roots(), [empty]);
        assert_eq!(Layout::Freedom.freedom_roots(), [[FREEDOM_DIR]]);
        assert_eq!(Layout::Pending.freedom_roots(), [empty, &[FREEDOM_DIR]]);
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
        }
    }

    fn state(at_root: Found, moved: Found, moving: Found) -> EntryState {
        EntryState {
            at_root,
            moved,
            moving,
        }
    }

    #[test]
    fn rollback_puts_back_what_moved_and_guesses_nothing() {
        use Found::*;
        let steps = |remove_moving, remove_placeholder, rename_back| Steps {
            remove_moving,
            remove_placeholder,
            rename_back,
        };
        // Not moved yet; moved; the placeholder in its place.
        assert_eq!(
            rollback("settings.json", state(File, Missing, Missing)),
            Ok(Steps::default())
        );
        assert_eq!(
            rollback("ipfs-data", state(Missing, Dir, Missing)),
            Ok(steps(false, false, true))
        );
        assert_eq!(
            rollback("identity", state(File, Dir, Missing)),
            Ok(steps(false, true, true))
        );
        // A symlink moved as itself goes back.
        assert_eq!(
            rollback("tor-data", state(Missing, Other, Missing)),
            Ok(steps(false, false, true))
        );
        // A copy cut short, its source still at the root.
        assert_eq!(
            rollback("ant-data", state(Dir, Missing, Dir)),
            Ok(steps(true, false, false))
        );
        // Guesses refused. Nowhere: the journal lists only entries present,
        // and no step of the move removes every copy of one.
        assert_eq!(
            rollback("run", state(Missing, Missing, Missing)),
            Err(Unsettled::Nowhere)
        );
        assert_eq!(
            rollback("ant-data", state(Missing, Missing, Dir)),
            Err(Unsettled::MovingWithoutSource)
        );
        assert_eq!(
            rollback("ant-data", state(Dir, Dir, Missing)),
            Err(Unsettled::AtBoth)
        );
        assert_eq!(
            rollback("settings.json", state(File, File, Missing)),
            Err(Unsettled::AtBoth)
        );
        // A file at `identity` is the placeholder only beside a moved
        // directory, and only for `identity`.
        assert_eq!(
            rollback("identity", state(File, File, Missing)),
            Err(Unsettled::AtBoth)
        );
        assert_eq!(
            rollback("identity", state(Dir, Dir, Missing)),
            Err(Unsettled::AtBoth)
        );
    }

    #[test]
    fn roll_forward_keeps_what_moved_and_removes_nothing() {
        use Found::*;
        for ok in [
            state(Missing, Dir, Missing),
            state(File, Dir, Missing),
            state(Dir, Dir, Missing),
        ] {
            assert_eq!(roll_forward(ok), Ok(()), "{ok:?}");
        }
        assert_eq!(
            roll_forward(state(Missing, Missing, Missing)),
            Err(Unsettled::Nowhere)
        );
        for unsettled in [
            state(Missing, Dir, Dir),
            state(Dir, Missing, Missing),
            state(File, Missing, Missing),
        ] {
            assert_eq!(roll_forward(unsettled), Err(Unsettled::NotMoved));
        }
    }
}
