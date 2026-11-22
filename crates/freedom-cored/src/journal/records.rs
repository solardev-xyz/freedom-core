//! What a pending node record's recovery needs, prepared before `serve`
//! confines itself (design 0017, C3 and C6).
//!
//! - **The plan (C6):** [`plan`] reads the journal and the intent as
//!   [`super::recover`] reads them, with the same bounds and validity checks
//!   and the done list, and names what recovery will reach, by record kind
//!   and node. It reads only: nothing is made, removed or locked.
//! - **The Radicle gate files (C3):** [`prepare`] opens, unlocked, the gate
//!   file of the `--node-root radicle=` home and of each Radicle home the
//!   plan names ([`RadicleGates`]). Recovery and `nodes.write_identity` lock
//!   such a file ([`super::home_gate`]) instead of opening a path in the
//!   lock directory, which a confined `serve` can't reach.
//! - **The grant:** the roots the plan names that exist, and each planned
//!   Radicle home once its gate file is open at it ([`Prepared::grant`]).
//!   D7-2d adds them to `confine`'s `read_write` (C2).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fc_service::gate::{GateError, GateFile};

use super::{
    Intent, JOURNAL, Journal, RADICLE_GATE, STAGING, read_done, read_journal, read_record,
    valid_intent, valid_journal,
};

/// A Radicle home whose gate file to open (C3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedHome {
    pub home: PathBuf,
    /// A committed journal's home: recovery takes its gate through the
    /// creating path (`radicle_gate(…, true)`), which makes a missing home,
    /// so its gate file is opened through that path too
    /// ([`GateFile::open`]). An intent's home must exist
    /// ([`GateFile::open_existing`]).
    pub create: bool,
}

/// What recovery will reach (C6). Recovery acts on one record per pass, so
/// there is at most one root here.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecordPlan {
    /// Bee roots to grant: each a directory now, following links, as
    /// recovery opens it (`Resolve::Follow`).
    pub grant: Vec<PathBuf>,
    /// Radicle homes whose gate files to open, each granted once its gate
    /// file is open at it.
    pub homes: Vec<PlannedHome>,
}

/// C6's plan, mirroring [`super::recover`]:
///
/// - **No record, an unreadable one, or an invalid one:** nothing. Recovery
///   fails on an unreadable record, or sets an invalid journal aside or
///   removes an invalid intent, with the identity directory alone.
/// - **A committed Bee journal not yet done:** its root, only if it is a
///   directory now (links followed). A missing one is neither created nor
///   granted: recovery concludes with no root (`Corrupt`), as today.
/// - **A committed Radicle journal not yet done:** its home, whose gate
///   file is opened through the creating path, which makes a missing home
///   as recovery's gate would.
/// - **An intent, no journal:** a Bee root that is a directory, following
///   links (a dangling link is a missing root); a Radicle home that is a
///   directory through no link, with its gate file. A missing root is
///   neither created nor granted (recovery removes the intent without the
///   gate and without looking under it); one that isn't a directory isn't
///   granted (recovery fails on it, as today).
/// - **A journal the done list records, or an invalid one,** grants nothing
///   of its own. Recovery removes it, or sets it aside, and leaves the
///   intent for its next pass in the same run (before the next node write),
///   so the intent is planned as if there were no journal.
///
/// A root replaced or made after the plan is outside it (C6, "A root
/// replaced or made during start-up"): the plan adds no identity check of
/// its own.
pub fn plan(identity_dir: &Path) -> RecordPlan {
    let mut plan = RecordPlan::default();
    // Read as recovery reads it: the same handle kind and bounds.
    match read_journal(&identity_dir.join(JOURNAL)) {
        Err(_) => return plan,
        Ok(None) => {}
        Ok(Some((bytes, _))) => {
            if let Ok(journal) = serde_json::from_slice::<Journal>(&bytes)
                && valid_journal(&journal, identity_dir)
            {
                match read_done(identity_dir) {
                    Err(_) => return plan,
                    Ok(done) if done.ops.iter().any(|op| op.op_id == journal.op_id) => {}
                    Ok(_) => {
                        plan.committed(&journal.node, journal.root);
                        return plan;
                    }
                }
            }
        }
    }
    plan.intent(identity_dir);
    plan
}

impl RecordPlan {
    fn committed(&mut self, node: &str, root: PathBuf) {
        match node {
            "bee" if followed_dir(&root) => self.grant.push(root),
            "radicle" => self.homes.push(PlannedHome {
                home: root,
                create: true,
            }),
            _ => {}
        }
    }

    fn intent(&mut self, identity_dir: &Path) {
        let Ok(Some(bytes)) = read_record(&identity_dir.join(STAGING)) else {
            return;
        };
        let Ok(intent) = serde_json::from_slice::<Intent>(&bytes) else {
            return;
        };
        if !valid_intent(&intent, identity_dir) {
            return;
        }
        match intent.node.as_str() {
            "bee" if followed_dir(&intent.root) => self.grant.push(intent.root),
            "radicle"
                if std::fs::symlink_metadata(&intent.root).is_ok_and(|found| found.is_dir()) =>
            {
                self.homes.push(PlannedHome {
                    home: intent.root,
                    create: false,
                });
            }
            _ => {}
        }
    }
}

/// A directory at `root`, links followed: what recovery's `Resolve::Follow`
/// opens. Missing, a dangling link, or anything else: not one.
fn followed_dir(root: &Path) -> bool {
    std::fs::metadata(root).is_ok_and(|found| found.is_dir())
}

/// The Radicle homes' gate files `serve` opened ahead (design 0017, C3),
/// unlocked, keyed by canonical home. Clones share the open files.
#[derive(Debug, Clone, Default)]
pub struct RadicleGates {
    files: BTreeMap<PathBuf, GateFile>,
    /// `--node-root radicle=` as main names it, and its canonical home:
    /// `nodes.write_identity` names the home main's way.
    argument: Option<(PathBuf, PathBuf)>,
}

impl RadicleGates {
    /// The gate file of `home`: its canonical home's, or the argument's when
    /// `home` is the argument as main names it.
    pub fn get(&self, home: &Path) -> Option<&GateFile> {
        self.files.get(home).or_else(|| {
            let (named, canonical) = self.argument.as_ref()?;
            if named == home {
                self.files.get(canonical)
            } else {
                None
            }
        })
    }

    /// The number of open gate files.
    pub fn count(&self) -> usize {
        self.files.len()
    }

    /// The open files' descriptors, which cross `confine` (C2's
    /// `descriptors`): one each on Unix, none elsewhere. D7-2d passes them.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn descriptors(&self) -> Vec<i32> {
        self.files
            .values()
            .flat_map(GateFile::descriptors)
            .collect()
    }

    /// Keeps `file` under its canonical home, unless a file is kept there
    /// already: the first stays, so one home has one open file.
    fn keep(&mut self, file: GateFile) {
        self.files
            .entry(file.data_dir().to_path_buf())
            .or_insert(file);
    }
}

/// What `serve` prepares before its threads (design 0017, C3 and C6).
#[derive(Debug, Default)]
pub struct Prepared {
    /// The roots C6 adds to `confine`'s `read_write` (C2): each Bee root
    /// the plan names, a directory when planned, and each planned Radicle
    /// home whose gate file is open at it (a committed journal's made by
    /// that open). Unused until D7-2d confines `serve`.
    pub grant: Vec<PathBuf>,
    /// The gate files opened: the `--node-root radicle=` home's, made if
    /// missing as fc-service's gate makes it, and each planned home's.
    pub gates: RadicleGates,
}

/// Plans the records in `identity_dir` ([`plan`]) and opens the Radicle
/// gate files in `lock_dir`: first `radicle_root`'s (`--node-root
/// radicle=`), then each planned home's not opened already. A planned home
/// whose gate file opens at another canonical home (a link on its path) is
/// neither kept nor granted: recovery refuses such a home, as today. A
/// gate file that can't be opened is logged and left out, and the gate is
/// then taken by its path as before 0017, which fails as it does today.
pub fn prepare(identity_dir: &Path, lock_dir: &Path, radicle_root: Option<&Path>) -> Prepared {
    let mut prepared = Prepared::default();
    if let Some(home) = radicle_root {
        match GateFile::open(home, lock_dir, RADICLE_GATE) {
            Ok(file) => {
                prepared.gates.argument = Some((home.to_path_buf(), file.data_dir().to_path_buf()));
                prepared.gates.keep(file);
            }
            Err(e) => unopened(&e),
        }
    }
    let plan = plan(identity_dir);
    prepared.grant = plan.grant;
    for PlannedHome { home, create } in plan.homes {
        if prepared.gates.get(&home).is_none() {
            let opened = if create {
                GateFile::open(&home, lock_dir, RADICLE_GATE)
            } else {
                GateFile::open_existing(&home, lock_dir, RADICLE_GATE)
            };
            match opened {
                Ok(file) if file.data_dir() == home => prepared.gates.keep(file),
                Ok(_) => continue,
                Err(e) => {
                    unopened(&e);
                    continue;
                }
            }
        }
        if prepared
            .gates
            .get(&home)
            .is_some_and(|file| file.data_dir() == home)
        {
            prepared.grant.push(home);
        }
    }
    prepared
}

fn unopened(error: &GateError) {
    crate::log::error(
        "cannot open a Radicle home's gate file",
        serde_json::json!({ "error": error.to_string() }),
    );
}

#[cfg(test)]
mod tests {
    use super::super::{
        FileSpec, Gates, JournalFile, OpStatus, Recovered, finish, hex, layout, put_record,
        recover, stage, staged_path, write_root,
    };
    use super::*;
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    /// A test's directories: canonical, as the gates resolve them (macOS's
    /// `/var` is a link).
    struct World {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        identity: PathBuf,
        locks: PathBuf,
    }

    fn world() -> World {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let identity = base.join("identity");
        std::fs::create_dir(&identity).unwrap();
        // As `serve`'s own gate leaves it before anything here runs.
        let locks = base.join("locks");
        std::fs::create_dir(&locks).unwrap();
        World {
            _tmp: tmp,
            identity,
            locks,
            base,
        }
    }

    impl World {
        /// Recovery's gates with `files`, and no way to a gate by its path:
        /// the lock directory they name is a regular file, so a gate is
        /// taken through `files` or not at all.
        fn only_through(&self, files: &RadicleGates) -> Gates {
            let blocked = self.base.join("not-a-lock-dir");
            std::fs::write(&blocked, b"").unwrap();
            Gates {
                lock_dir: blocked,
                retry: Duration::ZERO,
                held: None,
                held_identity: None,
                files: files.clone(),
            }
        }

        /// Today's gates: by path, in the real lock directory.
        fn by_path(&self) -> Gates {
            Gates {
                lock_dir: self.locks.clone(),
                retry: Duration::ZERO,
                held: None,
                held_identity: None,
                files: RadicleGates::default(),
            }
        }

        fn prepare(&self, radicle_root: Option<&Path>) -> Prepared {
            prepare(&self.identity, &self.locks, radicle_root)
        }

        /// `paths`, under the base.
        fn at(&self, paths: &[&str]) -> Vec<PathBuf> {
            paths.iter().map(|path| self.base.join(path)).collect()
        }

        /// Everything under the base but the lock directories, relative:
        /// each path, and a file's bytes or a link's target, with the base
        /// itself written `<base>` (records name absolute paths).
        fn tree(&self) -> Vec<(PathBuf, String)> {
            fn walk(base: &Path, dir: &Path, out: &mut Vec<(PathBuf, String)>) {
                let mut entries: Vec<_> = std::fs::read_dir(dir)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect();
                entries.sort();
                for path in entries {
                    let relative = path.strip_prefix(base).unwrap().to_path_buf();
                    if relative == Path::new("locks") || relative == Path::new("not-a-lock-dir") {
                        continue;
                    }
                    let kind = std::fs::symlink_metadata(&path).unwrap();
                    if kind.is_symlink() {
                        let target = std::fs::read_link(&path).unwrap();
                        let target = target.strip_prefix(base).unwrap_or(&target);
                        out.push((relative, format!("-> {}", target.display())));
                    } else if kind.is_dir() {
                        out.push((relative, "/".into()));
                        walk(base, &path, out);
                    } else {
                        let bytes = std::fs::read(&path).unwrap();
                        let text = String::from_utf8_lossy(&bytes)
                            .replace(base.to_str().unwrap(), "<base>");
                        out.push((relative, text));
                    }
                }
            }
            let mut out = Vec::new();
            walk(&self.base, &self.base, &mut out);
            out
        }
    }

    /// A committed journal for `node` under `root`, today's form, as a
    /// writer leaves it after its commit: each file staged beside its target
    /// when `staged`.
    fn committed(w: &World, op_id: &str, node: &str, root: &Path, staged: bool) {
        let files = layout(node, root)
            .unwrap()
            .into_iter()
            .map(|target| {
                let contents = format!("new {}", target.file_name().unwrap().to_string_lossy());
                if staged {
                    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                    std::fs::write(staged_path(&target), &contents).unwrap();
                }
                JournalFile {
                    staged: Some(staged_path(&target)),
                    sha256: Some(hex(&Sha256::digest(contents.as_bytes()))),
                    target,
                    remove: false,
                }
            })
            .collect();
        let journal = Journal {
            op_id: op_id.into(),
            node: node.into(),
            root: root.to_owned(),
            files,
            wipe: Vec::new(),
        };
        std::fs::write(
            w.identity.join(JOURNAL),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
    }

    /// An intent for `node` under `root`, with its files staged when the
    /// root is a directory and `staged`.
    fn intent(w: &World, op_id: &str, node: &str, root: &Path, staged: bool) {
        put_record(
            &w.identity,
            STAGING,
            &Intent {
                op_id: op_id.into(),
                node: node.into(),
                root: root.to_owned(),
            },
        )
        .unwrap();
        if staged {
            let top = write_root("bee", root, None).unwrap();
            for target in layout(node, root).unwrap() {
                stage(
                    &top,
                    &FileSpec {
                        target,
                        contents: b"staged",
                    },
                )
                .unwrap();
            }
        }
    }

    /// One case, built twice: recovered today (gates by path, no gate
    /// file), and after [`prepare`] with recovery's gates only through the
    /// files it opened. Both recoveries end the same, and leave the same
    /// tree. The prepared world's plan and recovery are returned.
    fn both(
        radicle_root: Option<&str>,
        build: impl Fn(&World),
    ) -> (World, Prepared, std::io::Result<Recovered>) {
        let today = world();
        build(&today);
        let recovered_today = recover(&today.identity, &today.by_path());

        let w = world();
        build(&w);
        let root = radicle_root.map(|root| w.base.join(root));
        let prepared = w.prepare(root.as_deref());
        let recovered = recover(&w.identity, &w.only_through(&prepared.gates));

        match (&recovered_today, &recovered) {
            (Ok(today), Ok(now)) => assert_eq!(today, now),
            (Err(_), Err(_)) => {}
            other => panic!("recovery changed: {other:?}"),
        }
        // The argument's home is made by its gate file: today's start
        // doesn't make it.
        let argument = root.map(|root| root.strip_prefix(&w.base).unwrap().to_path_buf());
        let tree = |world: &World| -> Vec<_> {
            world
                .tree()
                .into_iter()
                .filter(|(path, _)| argument.as_ref().is_none_or(|home| !path.starts_with(home)))
                .collect()
        };
        assert_eq!(tree(&today), tree(&w));
        (w, prepared, recovered)
    }

    fn finished(op_id: &str, node: &str, status: OpStatus) -> Recovered {
        Recovered::Finished {
            op_id: op_id.into(),
            node: node.into(),
            status,
        }
    }

    /// A committed journal, root there: Bee's root granted as it is;
    /// Radicle's home granted with its gate file, through which recovery
    /// finishes it.
    #[test]
    fn a_committed_journals_root_is_granted() {
        for node in ["bee", "radicle"] {
            let (w, prepared, recovered) = both(None, |w| {
                std::fs::create_dir(w.base.join("root")).unwrap();
                committed(w, "op", node, &w.base.join("root"), true);
            });
            assert_eq!(prepared.grant, w.at(&["root"]), "{node}");
            assert_eq!(prepared.gates.count(), usize::from(node == "radicle"));
            assert_eq!(
                recovered.unwrap(),
                finished("op", node, OpStatus::Installed),
                "{node}"
            );
        }
    }

    /// A committed journal, root gone with its parent: Bee's isn't made or
    /// granted, and recovery concludes it `Corrupt`; Radicle's home is made
    /// by its gate file's creating path, as recovery's gate makes it today,
    /// granted, and concluded `Corrupt` too.
    #[test]
    fn a_committed_journals_missing_root() {
        let (w, prepared, recovered) = both(None, |w| {
            committed(w, "op", "bee", &w.base.join("gone/root"), false);
        });
        assert!(prepared.grant.is_empty());
        assert_eq!(recovered.unwrap(), finished("op", "bee", OpStatus::Corrupt));
        assert!(!w.base.join("gone").exists());

        let w = world();
        committed(&w, "op", "radicle", &w.base.join("gone/home"), false);
        let prepared = w.prepare(None);
        assert!(w.base.join("gone/home").is_dir(), "the home wasn't made");
        assert_eq!(prepared.grant, w.at(&["gone/home"]));
        assert_eq!(prepared.gates.count(), 1);
        let recovered = recover(&w.identity, &w.only_through(&prepared.gates));
        assert_eq!(
            recovered.unwrap(),
            finished("op", "radicle", OpStatus::Corrupt)
        );
        let (_, _, recovered) = both(None, |w| {
            committed(w, "op", "radicle", &w.base.join("gone/home"), false);
        });
        assert_eq!(
            recovered.unwrap(),
            finished("op", "radicle", OpStatus::Corrupt)
        );
    }

    /// A committed journal whose root isn't the current `--node-root`
    /// (main's directory moved since): the record's root is planned, beside
    /// the argument's gate file, and recovery finishes it there.
    #[test]
    fn a_committed_journals_root_changed_since_the_arguments() {
        for node in ["bee", "radicle"] {
            let (w, prepared, recovered) = both(Some("current"), |w| {
                std::fs::create_dir(w.base.join("old")).unwrap();
                committed(w, "op", node, &w.base.join("old"), true);
            });
            assert_eq!(prepared.grant, w.at(&["old"]), "{node}");
            // The argument's, and the old home's for Radicle.
            assert_eq!(prepared.gates.count(), 1 + usize::from(node == "radicle"));
            assert!(prepared.gates.get(&w.base.join("current")).is_some());
            assert_eq!(
                recovered.unwrap(),
                finished("op", node, OpStatus::Installed),
                "{node}"
            );
            let config = if node == "bee" {
                "config.yaml"
            } else {
                "config.json"
            };
            assert_eq!(
                std::fs::read_to_string(w.base.join("old").join(config)).unwrap(),
                format!("new {config}")
            );
        }
    }

    /// The Radicle service holds the home's gate: recovery, through the
    /// gate file opened ahead, waits, as today, and the journal stays.
    /// Released, the next recovery finishes it through the same file.
    #[test]
    fn a_held_radicle_gate_makes_recovery_wait() {
        let w = world();
        let home = w.base.join("home");
        std::fs::create_dir(&home).unwrap();
        committed(&w, "op", "radicle", &home, true);
        let prepared = w.prepare(None);
        let service = fc_service::gate::acquire(&home, &w.locks, RADICLE_GATE, Duration::ZERO)
            .expect("the service's gate");
        let gates = w.only_through(&prepared.gates);
        let waiting = Recovered::Waiting {
            op_id: "op".into(),
            node: "radicle".into(),
        };
        assert_eq!(recover(&w.identity, &gates).unwrap(), waiting);
        assert!(w.identity.join(JOURNAL).exists());
        // Today's, by path, the same.
        assert_eq!(recover(&w.identity, &w.by_path()).unwrap(), waiting);
        // A gate this process holds through the same file is contention
        // too.
        drop(service);
        let own = prepared.gates.get(&home).unwrap().lock(Duration::ZERO);
        assert_eq!(recover(&w.identity, &gates).unwrap(), waiting);
        drop(own);
        assert_eq!(
            recover(&w.identity, &gates).unwrap(),
            finished("op", "radicle", OpStatus::Installed)
        );
    }

    /// An intent whose root is there: granted (Radicle with its gate file),
    /// and recovery removes its staged files through that gate.
    #[test]
    fn an_intents_root_is_granted() {
        for node in ["bee", "radicle"] {
            let (w, prepared, recovered) = both(None, |w| {
                intent(w, "op", node, &w.base.join("root"), true);
            });
            assert_eq!(prepared.grant, w.at(&["root"]), "{node}");
            assert_eq!(prepared.gates.count(), usize::from(node == "radicle"));
            assert_eq!(recovered.unwrap(), Recovered::Discarded, "{node}");
            assert!(!w.base.join("root/config.json.freedom-new").exists());
        }
    }

    /// An intent whose root is missing: nothing is made, opened or granted,
    /// and recovery removes the intent.
    #[test]
    fn an_intents_missing_root_is_neither_made_nor_granted() {
        for node in ["bee", "radicle"] {
            let (w, prepared, recovered) = both(None, |w| {
                intent(w, "op", node, &w.base.join("gone/root"), false);
            });
            assert!(prepared.grant.is_empty(), "{node}");
            assert_eq!(prepared.gates.count(), 0);
            assert_eq!(recovered.unwrap(), Recovered::Discarded, "{node}");
            assert!(!w.base.join("gone").exists(), "{node}");
            assert_eq!(std::fs::read_dir(&w.locks).unwrap().count(), 0);
        }
    }

    /// An intent whose root isn't a directory: not granted, no gate file,
    /// and recovery fails on it, as today; the intent stays.
    #[test]
    fn an_intents_root_that_isnt_a_directory_isnt_granted() {
        for node in ["bee", "radicle"] {
            let (w, prepared, recovered) = both(None, |w| {
                std::fs::write(w.base.join("root"), b"a file").unwrap();
                intent(w, "op", node, &w.base.join("root"), false);
            });
            assert!(prepared.grant.is_empty(), "{node}");
            assert_eq!(prepared.gates.count(), 0);
            assert!(recovered.is_err(), "{node}");
            assert!(w.identity.join(STAGING).exists());
        }
    }

    /// Bee follows links: a link to a directory is granted as named, and a
    /// dangling one is a missing root, discarded as today. Radicle's home
    /// goes through no link: a link to a directory isn't granted, and
    /// recovery refuses it, as today.
    #[cfg(unix)]
    #[test]
    fn bee_follows_a_link_and_radicle_takes_none() {
        let (w, prepared, recovered) = both(None, |w| {
            std::os::unix::fs::symlink(w.base.join("nowhere"), w.base.join("link")).unwrap();
            intent(w, "op", "bee", &w.base.join("link"), false);
        });
        assert!(prepared.grant.is_empty());
        assert_eq!(recovered.unwrap(), Recovered::Discarded);
        assert!(!w.base.join("nowhere").exists());

        let (w, prepared, recovered) = both(None, |w| {
            std::fs::create_dir(w.base.join("real")).unwrap();
            std::os::unix::fs::symlink(w.base.join("real"), w.base.join("link")).unwrap();
            intent(w, "op", "bee", &w.base.join("link"), false);
        });
        assert_eq!(prepared.grant, w.at(&["link"]));
        assert_eq!(recovered.unwrap(), Recovered::Discarded);

        let (_, prepared, recovered) = both(None, |w| {
            std::fs::create_dir(w.base.join("real")).unwrap();
            std::os::unix::fs::symlink(w.base.join("real"), w.base.join("link")).unwrap();
            intent(w, "op", "radicle", &w.base.join("link"), false);
        });
        assert!(prepared.grant.is_empty());
        assert_eq!(prepared.gates.count(), 0);
        assert!(recovered.is_err());

        // A committed Radicle journal whose home became a link since: its
        // gate file opens at the link's target, so it is neither kept nor
        // granted, and recovery refuses the home, as today.
        let (w, prepared, recovered) = both(None, |w| {
            std::fs::create_dir(w.base.join("real")).unwrap();
            std::os::unix::fs::symlink(w.base.join("real"), w.base.join("home")).unwrap();
            committed(w, "op", "radicle", &w.base.join("home"), false);
        });
        assert!(prepared.grant.is_empty());
        assert_eq!(prepared.gates.count(), 0);
        assert!(recovered.is_err());
        assert!(w.identity.join(JOURNAL).exists());
    }

    /// Records recovery never acts on grant nothing: an invalid journal, an
    /// invalid intent, an unreadable journal, and a journal the done list
    /// records.
    #[test]
    fn invalid_records_and_done_journals_grant_nothing() {
        let (_, prepared, recovered) = both(None, |w| {
            std::fs::create_dir(w.base.join("root")).unwrap();
            std::fs::write(
                w.identity.join(JOURNAL),
                serde_json::json!({ "op_id": "x", "node": "radicle", "root": w.base.join("root"),
                    "files": [] })
                .to_string(),
            )
            .unwrap();
        });
        assert_eq!(prepared.grant, Vec::<PathBuf>::new());
        assert_eq!(prepared.gates.count(), 0);
        assert_eq!(recovered.unwrap(), Recovered::Invalid);

        let (_, prepared, recovered) = both(None, |w| {
            std::fs::create_dir(w.base.join("root")).unwrap();
            intent(w, "not an op id", "bee", &w.base.join("root"), false);
        });
        assert!(prepared.grant.is_empty());
        assert_eq!(recovered.unwrap(), Recovered::Discarded);

        let (_, prepared, recovered) = both(None, |w| {
            std::fs::create_dir(w.identity.join(JOURNAL)).unwrap();
        });
        assert!(prepared.grant.is_empty());
        assert!(recovered.is_err());

        for node in ["bee", "radicle"] {
            let (_, prepared, recovered) = both(None, |w| {
                std::fs::create_dir(w.base.join("root")).unwrap();
                committed(w, "op", node, &w.base.join("root"), true);
                finish(&w.identity, "op", OpStatus::Installed).unwrap();
                committed(w, "op", node, &w.base.join("root"), true);
            });
            assert!(prepared.grant.is_empty(), "{node}");
            assert_eq!(prepared.gates.count(), 0);
            assert_eq!(recovered.unwrap(), Recovered::Cleaned, "{node}");
        }
    }

    /// An invalid journal set aside leaves the intent beside it for
    /// recovery's next pass in the same run: the intent is planned, and
    /// that pass gates its home through the file opened ahead.
    #[test]
    fn an_intent_behind_an_invalid_journal_is_planned() {
        let w = world();
        let home = w.base.join("home");
        intent(&w, "op", "radicle", &home, true);
        std::fs::write(w.identity.join(JOURNAL), b"{}").unwrap();
        let prepared = w.prepare(None);
        assert_eq!(prepared.grant, vec![home.clone()]);
        let gates = w.only_through(&prepared.gates);
        assert_eq!(recover(&w.identity, &gates).unwrap(), Recovered::Invalid);
        assert_eq!(recover(&w.identity, &gates).unwrap(), Recovered::Discarded);
        assert!(!home.join("config.json.freedom-new").exists());
    }

    /// C6's argument-root exception: a record whose missing root is the
    /// current `--node-root`, which C2 creates before the plan (simulated
    /// here; D7-2d does it). The plan finds it present and empty and grants
    /// it; recovery ends as it would with no root (`Corrupt` for a
    /// committed Bee journal, the intent removed), and the empty root stays.
    /// A Radicle journal's home is the argument's: one gate file serves
    /// both.
    #[test]
    fn a_missing_root_that_is_the_current_node_root() {
        let w = world();
        let root = w.base.join("bee");
        committed(&w, "op", "bee", &root, false);
        std::fs::create_dir(&root).unwrap();
        let prepared = w.prepare(None);
        assert_eq!(prepared.grant, vec![root.clone()]);
        assert_eq!(
            recover(&w.identity, &w.only_through(&prepared.gates)).unwrap(),
            finished("op", "bee", OpStatus::Corrupt)
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);

        let w = world();
        let root = w.base.join("bee");
        intent(&w, "op", "bee", &root, false);
        std::fs::create_dir(&root).unwrap();
        let prepared = w.prepare(None);
        assert_eq!(prepared.grant, vec![root.clone()]);
        assert_eq!(
            recover(&w.identity, &w.only_through(&prepared.gates)).unwrap(),
            Recovered::Discarded
        );
        assert!(root.is_dir());

        let w = world();
        let home = w.base.join("radicle");
        committed(&w, "op", "radicle", &home, false);
        let prepared = w.prepare(Some(&home));
        assert_eq!(prepared.grant, vec![home.clone()]);
        assert_eq!(prepared.gates.count(), 1);
        assert_eq!(
            recover(&w.identity, &w.only_through(&prepared.gates)).unwrap(),
            finished("op", "radicle", OpStatus::Corrupt)
        );
    }

    /// The argument's home, named through a link: kept under its canonical
    /// home and found by either name; a planned home that is its canonical
    /// path shares its file. Every file's descriptor is exposed.
    #[cfg(unix)]
    #[test]
    fn the_arguments_gate_file_is_found_by_either_name() {
        let w = world();
        let real = w.base.join("real");
        let named = w.base.join("named");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        committed(&w, "op", "radicle", &real, true);
        let prepared = w.prepare(Some(&named));
        assert_eq!(prepared.gates.count(), 1);
        assert_eq!(prepared.grant, vec![real.clone()]);
        let by_named = prepared.gates.get(&named).unwrap();
        let by_real = prepared.gates.get(&real).unwrap();
        assert_eq!(by_named.lock_path(), by_real.lock_path());
        assert_eq!(by_named.data_dir(), real);
        assert!(prepared.gates.get(&w.base.join("other")).is_none());
        assert_eq!(prepared.gates.descriptors(), by_real.descriptors());
        assert_eq!(prepared.gates.descriptors().len(), 1);
    }

    /// The argument's home missing: made by its gate file, as fc-service's
    /// gate makes it, private, with nothing in it.
    #[cfg(unix)]
    #[test]
    fn the_arguments_missing_home_is_made() {
        use std::os::unix::fs::PermissionsExt;
        let w = world();
        let home = w.base.join("profile/radicle");
        let prepared = w.prepare(Some(&home));
        assert_eq!(prepared.gates.count(), 1);
        assert!(prepared.grant.is_empty());
        let mode = std::fs::metadata(&home).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0);
    }
}
