//! Radicle homes with content, made by libradicle itself as a node makes
//! them, and the partial mutations a kill leaves, made with git directly.

use std::path::{Path, PathBuf};

use radicle::git::raw as git2;
use radicle::prelude::RepoId;
use serde_json::json;

/// A working copy with one commit on `master`.
fn working_copy(dir: &Path) {
    let repo = git2::Repository::init(dir).unwrap();
    std::fs::write(dir.join("README.md"), "# A fixture\n").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("README.md")).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Fixture", "fixture@example.invalid").unwrap();
    repo.commit(
        Some("refs/heads/master"),
        &signature,
        &signature,
        "First",
        &tree,
        &[],
    )
    .unwrap();
}

/// Runs a node on `home` as `seed`'s identity, reaching no one, and hands
/// it to `f`: isolated, and through the hermetic gate.
pub fn with_node<R>(
    home: &Path,
    seed: &[u8; 32],
    f: impl FnOnce(&mut libradicle::Embedded) -> R,
) -> R {
    let mut bytes = *seed;
    let key = libradicle::HostKey::from_bytes(&mut bytes).unwrap();
    let mut node = libradicle::Embedded::start_with_key(
        libradicle::Options {
            home: home.to_path_buf(),
            alias: "fixture".into(),
            listen: vec![],
            control_socket: false,
            routing: Some(libradicle::Routing {
                proxy: None,
                onion: radicle::node::config::AddressConfig::Drop,
                gate: super::hermetic::gate(),
            }),
            seeding_policy: None,
            isolated: true,
        },
        key,
    )
    .unwrap();
    let result = f(&mut node);
    node.shutdown().unwrap();
    result
}

/// Imports a repository into `home` as `seed`'s identity, with one issue.
pub fn repository(home: &Path, seed: &[u8; 32], name: &str) -> RepoId {
    let work = tempfile::tempdir().unwrap();
    working_copy(work.path());
    with_node(home, seed, |node| {
        let rid = node
            .import_repo(work.path(), name, "A fixture.", "master")
            .unwrap();
        node.create_issue(rid, "First", "Its description.", vec![])
            .unwrap();
        rid
    })
}

/// `rid`'s repository in `home`'s storage.
pub fn storage_of(home: &Path, rid: RepoId) -> PathBuf {
    home.join("storage").join(rid.canonical())
}

/// A ref of `namespace` in `rid`, set without signing it: what a kill
/// between a ref's update and its `rad/sigrefs` leaves.
pub fn unsigned_ref(home: &Path, rid: RepoId, namespace: &str) {
    let repo = git2::Repository::open_bare(storage_of(home, rid)).unwrap();
    let head = repo
        .refname_to_id(&format!("refs/namespaces/{namespace}/refs/heads/master"))
        .unwrap();
    repo.reference(
        &format!("refs/namespaces/{namespace}/refs/heads/unsigned"),
        head,
        true,
        "fixture",
    )
    .unwrap();
}

/// Whether `rid`'s `namespace` has the ref [`unsigned_ref`] sets.
pub fn has_unsigned_ref(home: &Path, rid: RepoId, namespace: &str) -> bool {
    git2::Repository::open_bare(storage_of(home, rid))
        .unwrap()
        .find_reference(&format!("refs/namespaces/{namespace}/refs/heads/unsigned"))
        .is_ok()
}

/// `rad/sigrefs` of `namespace` in `rid`.
pub fn sigrefs(home: &Path, rid: RepoId, namespace: &str) -> git2::Oid {
    git2::Repository::open_bare(storage_of(home, rid))
        .unwrap()
        .refname_to_id(&format!("refs/namespaces/{namespace}/refs/rad/sigrefs"))
        .unwrap()
}

/// The dirty marker, as the core's switch or a killed process leaves it.
pub fn mark(home: &Path, node_ids: &[&str]) {
    std::fs::create_dir_all(home.join("node")).unwrap();
    let mut node_ids = node_ids.to_vec();
    node_ids.sort_unstable();
    std::fs::write(
        home.join("node").join("dirty"),
        json!({ "node_ids": node_ids }).to_string(),
    )
    .unwrap();
}

/// The dirty marker's names, if there is one.
pub fn marked(home: &Path) -> Option<Vec<String>> {
    let bytes = std::fs::read(home.join("node").join("dirty")).ok()?;
    let marker: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    Some(
        marker["node_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect(),
    )
}

/// Another identity's seed, and its node ID.
pub const OTHER_SEED: [u8; 32] = [7; 32];

/// The node ID of `seed`'s key.
pub fn nid_of(seed: &[u8; 32]) -> String {
    let public = ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes();
    radicle::prelude::NodeId::from_bytes(public).to_human()
}

/// What `home`'s quarantine record says of each repository, for a failing
/// assertion: the evidence stays out of `rad.reconcile`'s reply.
pub fn evidence(home: &Path) -> String {
    let path = home.join("node").join("reconcile.db");
    if !path.exists() {
        return "no quarantine record".to_owned();
    }
    let record = radicle::storage::git::reconcile::quarantine::Quarantine::open(&path).unwrap();
    record
        .page(0, 16)
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {} {} {:?}: {}",
                r.rid, r.kind, r.step, r.unit, r.evidence
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}
