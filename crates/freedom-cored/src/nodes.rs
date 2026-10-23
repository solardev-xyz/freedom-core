//! Node identity files for `nodes.write_identity` (design 0001, "Phase 1
//! API"), built as freedom-browser's `identity/injection.js` writes them.
//! The multi-file commit itself is `journal.rs`.
//!
//! - **Bee** (`injectBeeIdentity`): `<data_dir>/keys/swarm.key`, the Bee
//!   wallet in an ethers keystore v3 under a fresh random password (32 bytes
//!   as hex), and `<data_dir>/config.yaml` from `createBeeConfig`'s template,
//!   which holds that password (K-3, Phase 5) and main's ports.
//! - **Radicle** (`injectRadicleKey`): `<home>/keys/radicle` (OpenSSH, the
//!   alias as comment), `<home>/keys/radicle.pub`, and `<home>/config.json`
//!   with `node.alias` set and every other setting kept, serialized like
//!   `JSON.stringify(config, null, 2)`.
//!
//! Stopping the node and wiping its stale state stay in main, before the
//! call (design 0001, "Ordering with the shell").
//!
//! **Radicle with `custody: "sealed"`** (design 0008, "The switch" and
//! "Identity changes"; the transitional selector, until the add-on goes):
//! no key file is written. The node key is released sealed to the Radicle
//! service at each start instead (`nodes.seal_radicle_key`). The write
//! removes `keys/radicle` and `keys/radicle.pub`, installs `config.json`,
//! and, when it removes a key file, first adds that identity's node ID to
//! the dirty marker, `node/dirty`. With `wipe`, it wipes `node/`, `cobs/`
//! and `storage/` first, as main did before. It needs no vault, and returns
//! no DID.

use std::path::{Path, PathBuf};

use fc_keys::freedom::FreedomKeys;
use fc_keys::keystore::{self, KeystoreParams};
use fc_keys::{multiformats, openssh};
use rand_core::TryCryptoRng;

use crate::anchor::{Dir, Kind};
use crate::journal;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// Which node, and where its files go (absolute paths from main).
#[derive(Debug)]
pub enum NodeSpec {
    Bee {
        data_dir: PathBuf,
        api_port: u16,
        p2p_port: u16,
    },
    Radicle {
        home: PathBuf,
        alias: String,
        custody: Custody,
    },
}

/// Which form of the Radicle write (design 0008, "The switch").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    /// Today's: the key pair is written, for the add-on.
    KeyFile,
    /// 0008's: no key file; any is removed. With `wipe`, the home's state
    /// goes too.
    Sealed { wipe: bool },
}

impl NodeSpec {
    pub fn name(&self) -> &'static str {
        match self {
            NodeSpec::Bee { .. } => "bee",
            NodeSpec::Radicle { .. } => "radicle",
        }
    }

    /// The directory the node's [`journal::layout`] is under.
    pub fn root(&self) -> &Path {
        match self {
            NodeSpec::Bee { data_dir, .. } => data_dir,
            NodeSpec::Radicle { home, .. } => home,
        }
    }
}

/// One file: where it goes, and its contents (wiped on drop).
pub type NodeFile = (PathBuf, Zeroizing<Vec<u8>>);

/// The files of one node identity, and its public identity for the reply.
pub struct NodeFiles {
    pub files: Vec<NodeFile>,
    /// `{ address }` for Bee, `{ did, node_id }` for Radicle.
    pub public: Map<String, Value>,
}

#[derive(Debug)]
pub enum BuildError {
    Keys,
    /// A path that isn't valid UTF-8 can't go into Bee's config.
    Path,
    /// Reading Radicle's existing config failed (not: it was malformed).
    Io(std::io::Error),
    /// Radicle's existing config isn't a regular file of at most
    /// [`journal::MAX_FILE`] (judged on the open handle).
    Config(&'static str),
    /// The switch can't name the identity it would remove: neither key
    /// file holds a readable public key, or the dirty marker can't be read
    /// (0008: `node_identity_corrupt`, and nothing is touched).
    IdentityCorrupt,
}

/// The node's files. `top` is its root, opened once by the writer
/// ([`journal::write_root`]): what is read of it (Radicle's config) is read
/// through that handle, as the journal stages and installs through it.
pub fn build<R: TryCryptoRng + ?Sized>(
    spec: &NodeSpec,
    top: &Dir,
    keys: &FreedomKeys,
    rng: &mut R,
) -> Result<NodeFiles, BuildError> {
    match spec {
        NodeSpec::Bee {
            data_dir,
            api_port,
            p2p_port,
        } => bee(keys, data_dir, *api_port, *p2p_port, rng),
        NodeSpec::Radicle { alias, .. } => radicle(keys, top, alias, rng),
    }
}

fn bee<R: TryCryptoRng + ?Sized>(
    keys: &FreedomKeys,
    data_dir: &Path,
    api_port: u16,
    p2p_port: u16,
    rng: &mut R,
) -> Result<NodeFiles, BuildError> {
    let dir = data_dir.to_str().ok_or(BuildError::Path)?;
    // generateBeeKeystorePassword: crypto.randomBytes(32).toString('hex').
    let mut raw = Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(raw.as_mut_slice())
        .map_err(|_| BuildError::Keys)?;
    let mut password = Zeroizing::new(String::with_capacity(64));
    for byte in raw.iter() {
        password.push(hex_digit(byte >> 4));
        password.push(hex_digit(byte & 0x0f));
    }
    let params = KeystoreParams::random(rng).map_err(|_| BuildError::Keys)?;
    let keystore =
        keystore::encrypt(&keys.bee_wallet, &password, &params).map_err(|_| BuildError::Keys)?;
    let mut config = Zeroizing::new(String::with_capacity(400 + dir.len()));
    config.push_str("# Bee Configuration (generated by identity injection)\n");
    config.push_str(&format!("api-addr: 127.0.0.1:{api_port}\n"));
    config.push_str(&format!("p2p-addr: :{p2p_port}\n"));
    config.push_str("swap-enable: false\n");
    config.push_str("mainnet: true\n");
    config.push_str("full-node: false\n");
    config.push_str("skip-postage-snapshot: true\n");
    config.push_str("resolver-options: https://ethereum.publicnode.com\n");
    config.push_str("storage-incentives-enable: false\n");
    config.push_str(&format!("data-dir: {dir}\n"));
    config.push_str("password: ");
    config.push_str(&password);
    config.push('\n');
    let mut public = Map::new();
    public.insert(
        "address".into(),
        Value::String(keys.bee_wallet.address().to_string()),
    );
    Ok(NodeFiles {
        files: in_layout(
            "bee",
            data_dir,
            vec![
                Zeroizing::new(keystore.into_bytes()),
                Zeroizing::new(config.as_bytes().to_vec()),
            ],
        )?,
        public,
    })
}

fn radicle<R: TryCryptoRng + ?Sized>(
    keys: &FreedomKeys,
    top: &Dir,
    alias: &str,
    rng: &mut R,
) -> Result<NodeFiles, BuildError> {
    let home = top.location();
    let public_key = keys.radicle.public_key();
    let private =
        openssh::private_key_file(&keys.radicle, alias, rng).map_err(|_| BuildError::Keys)?;
    let public_line = openssh::public_key_line(&public_key, alias);
    let existing = read_config(top)?;
    let config = radicle_config(existing.as_deref(), alias);
    let mut public = Map::new();
    public.insert(
        "did".into(),
        Value::String(multiformats::did_key(&public_key)),
    );
    public.insert(
        "node_id".into(),
        Value::String(multiformats::radicle_node_id(&public_key)),
    );
    Ok(NodeFiles {
        files: in_layout(
            "radicle",
            home,
            vec![
                Zeroizing::new(private.as_bytes().to_vec()),
                Zeroizing::new(public_line.into_bytes()),
                Zeroizing::new(config.into_bytes()),
            ],
        )?,
        public,
    })
}

/// One entry of a Radicle write with `custody: "sealed"`.
pub enum SealedEntry {
    Install(PathBuf, Zeroizing<Vec<u8>>),
    Remove(PathBuf),
}

/// What a Radicle write with `custody: "sealed"` does, in order, and what it
/// wipes first: one of the journal's Radicle shapes.
pub struct SealedPlan {
    pub entries: Vec<SealedEntry>,
    pub wipe: Vec<PathBuf>,
}

/// 0008's dirty marker: `node/dirty`, `{"node_ids":[…]}`, the node IDs of
/// every identity that may have left a partial mutation, sorted, each once.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    node_ids: Vec<String>,
}

/// Builds the sealed form of the Radicle write for the home `top`: the
/// gate's canonical path, opened once after the gate was taken
/// ([`journal::write_root`]). Called with the home's gate held: what it
/// reads can't change before the commit. Everything below the home is
/// reached from that handle, through no symlink ([`crate::anchor::Dir`]): a
/// symlinked `keys` or `node` is an error, and nothing is touched (review of
/// #177).
pub fn radicle_sealed(top: &Dir, alias: &str, wipe: bool) -> Result<SealedPlan, BuildError> {
    let home = top.location();
    let existing = read_config(top)?;
    let config = radicle_config(existing.as_deref(), alias);
    let key_file = home.join("keys").join("radicle");
    let key_present = match top.under(&key_file, false).map_err(BuildError::Io)? {
        Some((dir, name)) => dir.kind(&name).map_err(BuildError::Io)? != Kind::Missing,
        None => false,
    };
    // `node/` must be a real directory too, or not there: the marker goes in
    // it, and a wipe removes it.
    top.under(&journal::radicle_marker(home), false)
        .map_err(BuildError::Io)?;
    let mut entries = Vec::with_capacity(4);
    // The switch: the identity whose key file goes stays checked (0008).
    // With `wipe`, nothing is left to check.
    if key_present && !wipe {
        let node_id = old_node_id(top)?.ok_or(BuildError::IdentityCorrupt)?;
        let marker = journal::radicle_marker(home);
        let mut node_ids = match read_marker(top, &marker)? {
            Some(marker) => marker.node_ids,
            None => Vec::new(),
        };
        node_ids.push(node_id);
        node_ids.sort();
        node_ids.dedup();
        let encoded =
            serde_json::to_vec(&Marker { node_ids }).map_err(|_| BuildError::IdentityCorrupt)?;
        entries.push(SealedEntry::Install(marker, Zeroizing::new(encoded)));
    }
    entries.push(SealedEntry::Remove(key_file));
    entries.push(SealedEntry::Remove(home.join("keys").join("radicle.pub")));
    entries.push(SealedEntry::Install(
        home.join("config.json"),
        Zeroizing::new(config.into_bytes()),
    ));
    Ok(SealedPlan {
        entries,
        wipe: if wipe {
            journal::radicle_wipe(home)
        } else {
            Vec::new()
        },
    })
}

/// The node ID of the identity whose key file is in `home`: from the key
/// file's public part (OpenSSH carries it in the clear), streamed and
/// decoded only up to the public key ([`openssh::PublicKeyReader`]); or else
/// from `keys/radicle.pub`. The private section is never decoded. `None`
/// when neither yields one.
fn old_node_id(top: &Dir) -> Result<Option<String>, BuildError> {
    let keys = top.location().join("keys");
    let public = match private_file_public(top, &keys.join("radicle"))? {
        Some(public) => Some(public),
        None => public_line(top, &keys.join("radicle.pub"))?,
    };
    Ok(public.map(|public| multiformats::radicle_node_id(&public)))
}

/// The file `path` under the home `top`, opened for reading from its handle
/// through no symlink below it, if it is a regular file.
fn open_under(top: &Dir, path: &Path) -> Result<Option<std::fs::File>, BuildError> {
    let Some((dir, name)) = top.under(path, false).map_err(BuildError::Io)? else {
        return Ok(None);
    };
    match dir.open_regular(&name, false).map_err(BuildError::Io)? {
        crate::fsx::Regular::File(file) => Ok(Some(file)),
        crate::fsx::Regular::Missing | crate::fsx::Regular::Other => Ok(None),
    }
}

/// A private key file's public key, read 64 bytes at a time into a wiped
/// buffer and fed to the streaming reader, which stops at the public key.
fn private_file_public(top: &Dir, path: &Path) -> Result<Option<[u8; 32]>, BuildError> {
    use std::io::Read as _;
    let Some(file) = open_under(top, path)? else {
        return Ok(None);
    };
    let mut reader = openssh::PublicKeyReader::new();
    let mut chunk = Zeroizing::new([0u8; 64]);
    let mut source = (&file).take(journal::MAX_FILE);
    loop {
        let read = source.read(chunk.as_mut_slice()).map_err(BuildError::Io)?;
        if read == 0 {
            return Ok(reader.finish());
        }
        if let Some(found) = reader.feed(&chunk[..read]) {
            return Ok(found);
        }
    }
}

/// A public key line's key: public data, read whole (at most
/// [`journal::MAX_FILE`]).
fn public_line(top: &Dir, path: &Path) -> Result<Option<[u8; 32]>, BuildError> {
    let Some(file) = open_under(top, path)? else {
        return Ok(None);
    };
    let Some(bytes) = crate::fsx::read_at_most(&file, journal::MAX_FILE).map_err(BuildError::Io)?
    else {
        return Ok(None);
    };
    Ok(std::str::from_utf8(&bytes)
        .ok()
        .and_then(openssh::public_key_of_line))
}

/// The marker as it is, if there is one. One the core can't read, or that
/// isn't a regular file, is `IdentityCorrupt`: the switch can't add to what
/// it can't read, and never drops a name.
fn read_marker(top: &Dir, path: &Path) -> Result<Option<Marker>, BuildError> {
    let Some((dir, name)) = top.under(path, false).map_err(BuildError::Io)? else {
        return Ok(None);
    };
    match dir.open_regular(&name, false).map_err(BuildError::Io)? {
        crate::fsx::Regular::Missing => Ok(None),
        crate::fsx::Regular::Other => Err(BuildError::IdentityCorrupt),
        crate::fsx::Regular::File(file) => {
            let bytes = crate::fsx::read_at_most(&file, journal::MAX_FILE)
                .map_err(BuildError::Io)?
                .ok_or(BuildError::IdentityCorrupt)?;
            serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| BuildError::IdentityCorrupt)
        }
    }
}

/// Pairs contents with the node's layout (same order as `journal::layout`).
fn in_layout(
    node: &str,
    root: &Path,
    contents: Vec<Zeroizing<Vec<u8>>>,
) -> Result<Vec<NodeFile>, BuildError> {
    let targets = journal::layout(node, root).ok_or(BuildError::Keys)?;
    if targets.len() != contents.len() {
        return Err(BuildError::Keys);
    }
    Ok(targets.into_iter().zip(contents).collect())
}

/// Tightens a node identity written before the core to `0600` in place
/// (design 0001, "Writes and durability", existing files at adoption; #85):
/// the files of the node's [`journal::layout`] under `root`, as the core
/// itself writes them. JS wrote them under the umask, and nothing rewrites
/// them until the next forced injection. Only regular files the user owns
/// are touched, never through a symlink (`fsx::tighten`). Returns how many
/// it changed.
pub fn tighten_existing(node: &str, root: &Path) -> usize {
    let Some(files) = journal::layout(node, root) else {
        return 0;
    };
    let mut changed = 0;
    for file in files {
        match crate::fsx::tighten(&file) {
            Ok(true) => changed += 1,
            Ok(false) => {}
            Err(e) => crate::log::warn(
                "could not tighten a node identity file",
                serde_json::json!({ "node": node, "error": e.kind().to_string() }),
            ),
        }
    }
    changed
}

/// Radicle's existing config, `config.json` in the home `top`, read
/// through its handle: `None` if absent. It must be a regular file (a
/// symlink at it followed, as JS's readFileSync does) of bounded size,
/// judged on the open handle, so a FIFO can't block the worker, even one
/// swapped in after a check (#83). Invalid UTF-8 reads as unparseable, which
/// starts over as `{}` like the JS catch.
fn read_config(top: &Dir) -> Result<Option<String>, BuildError> {
    let name = std::ffi::OsStr::new("config.json");
    let file = match top.open_following(name).map_err(BuildError::Io)? {
        crate::fsx::Regular::Missing => return Ok(None),
        crate::fsx::Regular::Other => return Err(BuildError::Config("not_regular")),
        crate::fsx::Regular::File(file) => file,
    };
    let bytes = crate::fsx::read_at_most(&file, journal::MAX_FILE)
        .map_err(BuildError::Io)?
        .ok_or(BuildError::Config("too_large"))?;
    Ok(Some(String::from_utf8(bytes).unwrap_or_default()))
}

/// `injectRadicleKey`'s config merge: parse the existing config (anything
/// unparseable starts over as `{}`), set `node.alias`, keep everything else,
/// and serialize like `JSON.stringify(config, null, 2)` (no final newline).
///
/// Deviations, for configs JS can't handle sensibly: a top-level value that
/// isn't an object starts over as `{}`, and a `node` that isn't an object is
/// replaced by `{ alias }`.
pub fn radicle_config(existing: Option<&str>, alias: &str) -> String {
    let mut config = existing
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    match config.get_mut("node") {
        Some(Value::Object(node)) => {
            node.insert("alias".into(), Value::String(alias.to_owned()));
        }
        _ => {
            let mut node = Map::new();
            node.insert("alias".into(), Value::String(alias.to_owned()));
            config.insert("node".into(), Value::Object(node));
        }
    }
    let mut out = String::new();
    stringify(&js_order(Value::Object(config)), 0, &mut out);
    out
}

/// `JSON.stringify(value, null, 2)` for parsed JSON: two-space indentation,
/// JavaScript string escaping, and numbers as JavaScript's `Number` prints
/// them (parsed as doubles, as `JSON.parse` does).
fn stringify(value: &Value, depth: usize, out: &mut String) {
    let indent = |out: &mut String, depth: usize| {
        for _ in 0..depth {
            out.push_str("  ");
        }
    };
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&js_number(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => js_string(s, out),
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Array(items) => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                indent(out, depth + 1);
                stringify(item, depth + 1, out);
            }
            out.push('\n');
            indent(out, depth);
            out.push(']');
        }
        Value::Object(map) if map.is_empty() => out.push_str("{}"),
        Value::Object(map) => {
            out.push_str("{\n");
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                indent(out, depth + 1);
                js_string(key, out);
                out.push_str(": ");
                stringify(item, depth + 1, out);
            }
            out.push('\n');
            indent(out, depth);
            out.push('}');
        }
    }
}

/// JSON.stringify's string quoting.
fn js_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `Number.prototype.toString()` for a finite double (ECMAScript
/// Number::toString): the shortest round-trip digits, in plain notation for
/// exponents -7 < n <= 21, otherwise `d.ddde±n`.
fn js_number(x: f64) -> String {
    if x == 0.0 {
        return "0".into();
    }
    if !x.is_finite() {
        return "null".into();
    }
    // Rust's `{:e}` is the shortest round-trip representation: "d.ddde±x".
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len() as i64;
    let n = exp.parse::<i64>().unwrap_or(0) + 1;
    let mut out = String::new();
    if x < 0.0 {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n('0', (n - k) as usize));
    } else if 0 < n && n <= 21 {
        out.push_str(&digits[..n as usize]);
        out.push('.');
        out.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', (-n) as usize));
        out.push_str(&digits);
    } else {
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if n > 0 { '+' } else { '-' });
        out.push_str(&(n - 1).abs().to_string());
    }
    out
}

/// Reorders object keys as JavaScript enumerates them: array-index keys
/// ("0" to "4294967294", canonical) first in ascending order, then the rest
/// in insertion order. Applied recursively.
fn js_order(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut indices: Vec<(u32, String, Value)> = Vec::new();
            let mut rest: Vec<(String, Value)> = Vec::new();
            for (key, value) in map {
                let value = js_order(value);
                match array_index(&key) {
                    Some(index) => indices.push((index, key, value)),
                    None => rest.push((key, value)),
                }
            }
            indices.sort_by_key(|(index, _, _)| *index);
            let mut ordered = Map::new();
            for (_, key, value) in indices {
                ordered.insert(key, value);
            }
            for (key, value) in rest {
                ordered.insert(key, value);
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(js_order).collect()),
        other => other,
    }
}

/// A canonical array index: no sign, no leading zero, below 2^32 - 1.
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || (key.len() > 1 && key.starts_with('0')) {
        return None;
    }
    if !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    key.parse::<u32>().ok().filter(|&n| n != u32::MAX)
}

fn hex_digit(nibble: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(nibble & 0x0f)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radicle_config_merges_like_js() {
        assert_eq!(
            radicle_config(None, "FreedomBrowser"),
            "{\n  \"node\": {\n    \"alias\": \"FreedomBrowser\"\n  }\n}"
        );
        let existing =
            r#"{"preferredSeeds":["a@b:1"],"node":{"listen":[],"alias":"old"},"web":{}}"#;
        assert_eq!(
            radicle_config(Some(existing), "me"),
            "{\n  \"preferredSeeds\": [\n    \"a@b:1\"\n  ],\n  \"node\": {\n    \"listen\": [],\n    \"alias\": \"me\"\n  },\n  \"web\": {}\n}"
        );
        // Unparseable: start over, as the JS catch does.
        assert_eq!(
            radicle_config(Some("{oops"), "x"),
            radicle_config(None, "x")
        );
        // JavaScript key order: array indices first, ascending.
        assert_eq!(
            radicle_config(Some(r#"{"b":1,"2":2,"1":3,"01":4}"#), "x"),
            "{\n  \"1\": 3,\n  \"2\": 2,\n  \"b\": 1,\n  \"01\": 4,\n  \"node\": {\n    \"alias\": \"x\"\n  }\n}"
        );
    }

    #[test]
    fn numbers_and_strings_print_like_javascript() {
        // Expected values from node: JSON.stringify(JSON.parse(text)).
        let cases = [
            ("1.0", "1"),
            ("-0", "0"),
            ("12345678901234567890", "12345678901234567000"),
            ("1e21", "1e+21"),
            ("1e20", "100000000000000000000"),
            ("0.000001", "0.000001"),
            ("0.0000001", "1e-7"),
            ("1.5e-7", "1.5e-7"),
            ("123.456", "123.456"),
            ("-2.5e300", "-2.5e+300"),
            ("0.1", "0.1"),
        ];
        for (input, expected) in cases {
            let value: Value = serde_json::from_str(input).unwrap();
            assert_eq!(js_number(value.as_f64().unwrap()), expected, "{input}");
        }
        let mut out = String::new();
        js_string("a\"b\\c\n\u{1}\u{1f}é", &mut out);
        assert_eq!(out, r#""a\"b\\c\n\u0001\u001fé""#);
    }

    #[test]
    fn array_indices_are_canonical() {
        assert_eq!(array_index("0"), Some(0));
        assert_eq!(array_index("4294967294"), Some(4_294_967_294));
        assert_eq!(array_index("4294967295"), None);
        assert_eq!(array_index("01"), None);
        assert_eq!(array_index("-1"), None);
        assert_eq!(array_index(""), None);
    }
}
