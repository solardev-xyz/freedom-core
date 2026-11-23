//! The C core's store (design 0014, "The store and the lifetime lock" and
//! "Private sessions").
//!
//! - **On disk**, for a persistent process: one file per key in the chain's
//!   directory, written as a temporary file, fsync and rename. Stale
//!   temporary files are swept when the store opens.
//! - **In memory**, for a private or checkpoint process: nothing reaches the
//!   disk.
//!
//! Both hold the same bounds: a key is `[A-Za-z0-9_]{1,100}`, a value at
//! most [`MAX_VALUE`], and all values together at most [`MAX_TOTAL`]. A
//! write past a bound, or one the disk refuses, doesn't happen; the C core's
//! `set` returns nothing, so it reads the key as absent later, as after any
//! failed write. Only the verifier thread calls into the C core, so the
//! store is called from that thread alone; its lock only satisfies
//! `colibri_stateless::Storage`'s `Send + Sync`.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use fc_service::log;
use serde_json::json;

/// The largest value the store keeps: 4 MiB (0014, Budgets: the PAP
/// transaction cache reached 1,857,584 bytes over the vectors).
pub const MAX_VALUE: usize = 4 << 20;

/// All values together: 64 MiB.
pub const MAX_TOTAL: u64 = 64 << 20;

/// The longest key.
const MAX_KEY: usize = 100;

/// A temporary file's suffix. `.` isn't in a key, so no key's file ends in
/// it.
const TEMP_SUFFIX: &str = ".tmp";

/// `[A-Za-z0-9_]{1,100}`.
pub fn valid_key(key: &str) -> bool {
    (1..=MAX_KEY).contains(&key.len())
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Why a write didn't happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The key isn't `[A-Za-z0-9_]{1,100}`.
    Key,
    /// The value is over [`MAX_VALUE`].
    Value,
    /// The store would pass [`MAX_TOTAL`].
    Total,
    /// The disk refused it.
    Io,
}

impl Refused {
    fn name(self) -> &'static str {
        match self {
            Refused::Key => "key",
            Refused::Value => "value",
            Refused::Total => "total",
            Refused::Io => "io",
        }
    }
}

/// The sizes the store holds, for its bounds and `colibri.stats`.
#[derive(Debug, Default)]
struct Sizes {
    sizes: HashMap<String, u64>,
    total: u64,
}

impl Sizes {
    /// Whether `key` may hold `len` bytes, within the bounds.
    fn admits(&self, key: &str, len: usize) -> Result<(), Refused> {
        if !valid_key(key) {
            return Err(Refused::Key);
        }
        if len > MAX_VALUE {
            return Err(Refused::Value);
        }
        let old = self.sizes.get(key).copied().unwrap_or(0);
        let total = self.total - old + len as u64;
        if total > MAX_TOTAL {
            return Err(Refused::Total);
        }
        Ok(())
    }

    fn set(&mut self, key: &str, len: u64) {
        let old = self.sizes.insert(key.to_owned(), len).unwrap_or(0);
        self.total = self.total - old + len;
    }

    fn remove(&mut self, key: &str) {
        if let Some(old) = self.sizes.remove(key) {
            self.total -= old;
        }
    }
}

/// Where the values are.
enum Backing {
    Dir(PathBuf),
    Memory(HashMap<String, Vec<u8>>),
}

struct Inner {
    backing: Backing,
    sizes: Sizes,
}

/// The C core's store.
pub struct Store {
    inner: Mutex<Inner>,
}

impl Store {
    /// The store in memory, empty.
    pub fn memory() -> Store {
        Store {
            inner: Mutex::new(Inner {
                backing: Backing::Memory(HashMap::new()),
                sizes: Sizes::default(),
            }),
        }
    }

    /// The store on `dir`, which exists. It is a cache, so it opens within
    /// its bounds or not at all: stale temporary files are removed, a key's
    /// file past [`MAX_VALUE`] is removed, and if the rest is past
    /// [`MAX_TOTAL`] every key's file is. A file that isn't a key's is left
    /// alone and not counted; the C core never reads it.
    pub fn open(dir: &Path) -> io::Result<Store> {
        let mut sizes = Sizes::default();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let meta = entry.metadata()?;
            if !meta.is_file() {
                continue;
            }
            if name.ends_with(TEMP_SUFFIX) {
                fs::remove_file(entry.path())?;
            } else if valid_key(name) {
                if meta.len() > MAX_VALUE as u64 {
                    log::warn(
                        "a stored value past its bound is removed",
                        json!({ "bytes": meta.len() }),
                    );
                    fs::remove_file(entry.path())?;
                } else {
                    sizes.set(name, meta.len());
                }
            }
        }
        if sizes.total > MAX_TOTAL {
            log::warn(
                "the store past its bound is emptied",
                json!({ "bytes": sizes.total }),
            );
            for key in sizes.sizes.keys() {
                fs::remove_file(dir.join(key))?;
            }
            sizes = Sizes::default();
        }
        Ok(Store {
            inner: Mutex::new(Inner {
                backing: Backing::Dir(dir.to_path_buf()),
                sizes,
            }),
        })
    }

    /// All values together, in bytes.
    pub fn total(&self) -> u64 {
        self.lock().sizes.total
    }

    /// The number of keys.
    pub fn keys(&self) -> usize {
        self.lock().sizes.sizes.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps `value` under `key`, or says why not.
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), Refused> {
        let mut inner = self.lock();
        inner.sizes.admits(key, value.len())?;
        match &mut inner.backing {
            Backing::Memory(map) => {
                map.insert(key.to_owned(), value.to_vec());
            }
            Backing::Dir(dir) => write_atomically(dir, key, value).map_err(|_| Refused::Io)?,
        }
        inner.sizes.set(key, value.len() as u64);
        Ok(())
    }

    /// The value under `key`, if the store has one.
    pub fn read(&self, key: &str) -> Option<Vec<u8>> {
        if !valid_key(key) {
            return None;
        }
        let inner = self.lock();
        inner.sizes.sizes.get(key)?;
        match &inner.backing {
            Backing::Memory(map) => map.get(key).cloned(),
            Backing::Dir(dir) => fs::read(dir.join(key)).ok(),
        }
    }

    /// Removes `key`, if the store has it.
    pub fn remove(&self, key: &str) {
        if !valid_key(key) {
            return;
        }
        let mut inner = self.lock();
        let gone = match &mut inner.backing {
            Backing::Memory(map) => {
                map.remove(key);
                true
            }
            Backing::Dir(dir) => match fs::remove_file(dir.join(key)) {
                Ok(()) => true,
                Err(e) => e.kind() == io::ErrorKind::NotFound,
            },
        };
        if gone {
            inner.sizes.remove(key);
        }
    }
}

/// `dir/key` as a temporary file, fsync and rename.
fn write_atomically(dir: &Path, key: &str, value: &[u8]) -> io::Result<()> {
    let temp = dir.join(format!("{key}{TEMP_SUFFIX}"));
    let result = (|| {
        let mut file = fs::File::create(&temp)?;
        file.write_all(value)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, dir.join(key))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// The store as the C core holds it (`colibri_stateless::register_storage`
/// takes it by value).
pub struct StoreHandle(pub std::sync::Arc<Store>);

impl colibri_stateless::Storage for StoreHandle {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.0.read(key)
    }

    fn set(&self, key: &str, value: &[u8]) {
        if let Err(refused) = self.0.put(key, value) {
            // The key and value stay out of the log: a header's key names
            // the block read.
            log::warn(
                "a store write didn't happen",
                json!({ "reason": refused.name(), "bytes": value.len() }),
            );
        }
    }

    fn delete(&self, key: &str) {
        self.0.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "colibrid-store-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn keys() {
        assert!(valid_key("sync_1_1918"));
        assert!(valid_key(&"a".repeat(100)));
        for bad in ["", "a.b", "a-b", "a/b", "..", "ä", &"a".repeat(101)] {
            assert!(!valid_key(bad), "{bad:?}");
        }
    }

    fn bounds(store: &Store) {
        assert_eq!(store.put("a", b"one"), Ok(()));
        assert_eq!(store.read("a").as_deref(), Some(&b"one"[..]));
        assert_eq!(store.put("a.b", b"x"), Err(Refused::Key));
        assert_eq!(store.read("a.b"), None);
        assert_eq!(
            store.put("big", &vec![0; MAX_VALUE + 1]),
            Err(Refused::Value)
        );
        assert_eq!(store.read("big"), None);
        assert_eq!(store.put("big", &vec![0; MAX_VALUE]), Ok(()));
        for i in 0..14 {
            assert_eq!(
                store.put(&format!("k{i}"), &vec![1; MAX_VALUE]),
                Ok(()),
                "{i}"
            );
        }
        assert_eq!(store.total(), 15 * MAX_VALUE as u64 + 3);
        // A sixteenth value of 4 MiB passes 64 MiB by `a`'s 3 bytes.
        assert_eq!(store.put("k14", &vec![1; MAX_VALUE]), Err(Refused::Total));
        assert_eq!(store.read("k14"), None);
        store.remove("a");
        assert_eq!(store.put("k14", &vec![1; MAX_VALUE]), Ok(()));
        assert_eq!(store.total(), MAX_TOTAL);
        // Replacing a value counts its new size only.
        assert_eq!(store.put("k0", &vec![2; MAX_VALUE]), Ok(()));
        assert_eq!(store.read("k0").map(|v| v[0]), Some(2));
        assert_eq!(store.total(), MAX_TOTAL);
        store.remove("k0");
        assert_eq!(store.read("k0"), None);
        assert_eq!(store.keys(), 15);
        assert_eq!(store.total(), MAX_TOTAL - MAX_VALUE as u64);
    }

    #[test]
    fn a_reopened_store_is_held_to_its_bounds() {
        let dir = temp_dir();
        // A value past its bound, written outside the store: removed.
        fs::write(dir.join("states_1"), vec![0u8; MAX_VALUE + 1]).unwrap();
        fs::write(dir.join("small"), b"kept").unwrap();
        let store = Store::open(&dir).unwrap();
        assert!(!dir.join("states_1").exists());
        assert_eq!(store.read("states_1"), None);
        assert_eq!(store.read("small").as_deref(), Some(&b"kept"[..]));
        drop(store);
        // Sixteen values at the bound and one byte more: all emptied.
        for i in 0..16 {
            fs::write(dir.join(format!("k{i}")), vec![1u8; MAX_VALUE]).unwrap();
        }
        let store = Store::open(&dir).unwrap();
        assert_eq!(store.keys(), 0);
        assert_eq!(store.total(), 0);
        assert!(!dir.join("k0").exists() && !dir.join("small").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_bounds() {
        bounds(&Store::memory());
    }

    #[test]
    fn disk_bounds_and_reopen() {
        let dir = temp_dir();
        let store = Store::open(&dir).unwrap();
        bounds(&store);
        assert!(dir.join("big").is_file());
        drop(store);
        // A stale temporary file is swept; a file that isn't a key's stays,
        // uncounted.
        fs::write(dir.join("k1.tmp"), b"half").unwrap();
        fs::write(dir.join("notes.txt"), b"left").unwrap();
        let store = Store::open(&dir).unwrap();
        assert_eq!(store.keys(), 15);
        assert_eq!(store.total(), MAX_TOTAL - MAX_VALUE as u64);
        assert!(!dir.join("k1.tmp").exists());
        assert!(dir.join("notes.txt").exists());
        assert_eq!(store.read("notes.txt"), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
