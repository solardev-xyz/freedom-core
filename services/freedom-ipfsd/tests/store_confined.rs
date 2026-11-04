//! A disk store confined to its directory completes a statement that spills
//! past the page cache (design 0010, "What each service needs": SQLite's
//! temporary data stays in memory). The statement is `export_car`'s sort of
//! every block with its data, the store's largest: 4 MiB of blocks under a
//! 16 KiB page cache, past SQLite's 1 MiB before a sort spills.
//!
//! Each case runs in a child of its own (this binary again, with
//! `STORE_CONFINED_CASE` set), which confines itself to a fresh data
//! directory as the service does. With `TempStore::Memory`, the service's,
//! the sort completes. With `TempStore::Default`, the control, SQLite asks
//! for a temporary file outside the directory, confinement refuses it, and
//! the statement fails: so the case does spill.
//!
//! Linux, where the kernel has Landlock; elsewhere it does nothing yet.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

use std::process::Command;

use fc_service::confine::{self, Network, Policy, Status};
use freedom_ipfs_store::{SqliteBlockStore, StoreOptions, TempStore};

const CASE: &str = "STORE_CONFINED_CASE";
const DIR: &str = "STORE_CONFINED_DIR";

fn main() {
    if let Ok(case) = std::env::var(CASE) {
        child(&case);
        return;
    }
    parent();
}

fn child(case: &str) {
    let _ = confine::clean_entry();
    let dir = std::path::PathBuf::from(std::env::var(DIR).unwrap());
    let report = confine::confine(&Policy {
        read_write: vec![dir.clone()],
        read_only: Vec::new(),
        refer: false,
        min_abi: 1,
        network: Network::Offline,
        resolver: confine::Resolver::None,
        descriptors: Vec::new(),
        interface_index: false,
    })
    .unwrap();
    println!("FILES {}", report.files == Status::Enforced);
    let temp_store = match case {
        "memory" => TempStore::Memory,
        _ => TempStore::Default,
    };
    let store = SqliteBlockStore::open_with(
        dir.join("freedom-ipfs.sqlite3"),
        StoreOptions {
            temp_store,
            cache_kib: Some(16),
            ..StoreOptions::default()
        },
    )
    .unwrap();
    for i in 0..512u32 {
        let mut data = vec![0u8; 8192];
        data[..4].copy_from_slice(&i.to_be_bytes());
        let cid = freedom_ipfs_core::cid_from_data(freedom_ipfs_core::CODEC_RAW, &data);
        store.put_block(&cid, &data).unwrap();
    }
    match store.export_car() {
        Ok(car) => println!("SORTED {}", car.len() > 512 * 8192),
        Err(_) => println!("SORTED false"),
    }
}

fn run(case: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .env(CASE, case)
        .env(DIR, dir.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{case}: {:?} {text}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    text
}

fn parent() {
    #[cfg(target_os = "linux")]
    {
        let memory = run("memory");
        if !memory.contains("FILES true") {
            // No Landlock on this kernel: nothing is confined to test.
            println!("store_confined: files aren't confined here: {memory}");
            return;
        }
        assert!(memory.contains("SORTED true\n"), "memory: {memory}");
        // The control: the same sort needs a temporary file, refused.
        let default = run("default");
        assert!(default.contains("SORTED false\n"), "default: {default}");
        println!("store_confined: the spilling sort completes in memory, confined");
    }
}
