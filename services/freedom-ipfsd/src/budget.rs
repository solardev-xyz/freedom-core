//! The process's budgets (design 0007, "Budgets"): one memory budget and
//! one set of retrieval limits for every instance of the process, and what
//! each instance and the writer reserve of it as fixed.
//!
//! - **The memory budget,** by reservation: 192 MiB for the persistent
//!   process, 448 MiB for the ephemeral one. Every instance's builder gets
//!   it, so its fetches reserve their receive buffers from it, and its
//!   caches' fixed capacities are reserved from it when it starts.
//! - **Retrieval admission:** one [`SharedLimits`] of upstream's default
//!   sizes (256 block fetches, 16 HTTP provider requests, 32 Bitswap
//!   connections, 4 DHT queries), shared by every instance's builder.
//! - **The writer's data queue,** 16 MiB, reserved when the process starts
//!   ([`Budgets::new`]) and held for its life.
//! - **An instance's fixed reservation** ([`Fixed`]): its store's (a memory
//!   store's page cap, its block target plus 4 MiB; a disk store's 8 MiB
//!   page cache) and its caches' (the hot cache, the small-body and UnixFS
//!   metadata caches), reserved at once when its start is admitted.
//! - **Background queues** are upstream's, 64 items per instance, each
//!   node's own.

use fc_protocol::stream::WRITER_DATA_CAP;
use freedom_ipfs_core::Reservation;
use freedom_ipfs_gateway::{BudgetError, GatewayConfig, MemoryBudget, SharedLimits};
use freedom_ipfs_store::StoreOptions;

use crate::instances::Kind;
use crate::params::Store;
use crate::testhooks;

/// The persistent process's memory budget.
pub const PERSISTENT_MEMORY: usize = 192 << 20;
/// The ephemeral process's memory budget.
pub const EPHEMERAL_MEMORY: usize = 448 << 20;
/// A disk store's page cache (`PRAGMA cache_size`), reserved as fixed.
pub const DISK_PAGE_CACHE: usize = 8 << 20;
/// What a memory store's page cap holds besides its block target: metadata
/// and b-tree pages.
pub const MEMORY_STORE_OVERHEAD: u64 = 4 << 20;
/// A private instance's hot cache (0007, "Bounds": 4 MiB hot each).
pub const MEMORY_HOT_CACHE: u64 = 4 << 20;
/// The page size the page cap is counted in: SQLite's default for a new
/// database, which every memory store is.
pub const PAGE_SIZE: u64 = 4096;

/// The process's budgets.
pub struct Budgets {
    pub memory: MemoryBudget,
    pub limits: SharedLimits,
    /// The writer's data queue: held for the life of the process.
    _writer: Reservation,
}

impl Budgets {
    /// The budgets of a process of `kind`, with the writer's 16 MiB
    /// reserved. Fails only if the budget can't hold even that (a test's
    /// override).
    pub fn new(kind: &Kind) -> Result<Budgets, BudgetError> {
        let limit = match kind {
            Kind::Persistent { .. } => PERSISTENT_MEMORY,
            Kind::Ephemeral => EPHEMERAL_MEMORY,
        };
        let memory = MemoryBudget::new(testhooks::memory_budget(limit));
        let writer = memory.try_reserve(WRITER_DATA_CAP)?;
        Ok(Budgets {
            memory,
            limits: SharedLimits::default(),
            _writer: writer,
        })
    }
}

/// What an instance reserves as fixed, and how its store is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixed {
    /// The store's: its page cap, or its page cache.
    pub store: usize,
    /// The caches': the hot cache, and the gateway's two.
    pub caches: usize,
    pub options: StoreOptions,
}

impl Fixed {
    /// For a store of `store`'s kind and target, under `gateway`. The hot
    /// cache's part is upstream's own figure for the options
    /// ([`StoreOptions::hot_cache_fixed_bytes`]): what the opened store's
    /// hot cache holds, its own structures included, which a tiny target
    /// doesn't cover.
    pub fn of(store: Store, gateway: &GatewayConfig) -> Fixed {
        let (store_part, options) = match store {
            // Upstream's hot cache: `min(max_bytes, 16 MiB)`.
            Store::Disk { max_bytes } => (
                DISK_PAGE_CACHE,
                StoreOptions {
                    max_bytes,
                    hot_cache_bytes: None,
                    max_page_count: None,
                    cache_kib: u32::try_from(DISK_PAGE_CACHE >> 10).ok(),
                },
            ),
            Store::Memory { max_bytes } => {
                let cap = max_bytes.saturating_add(MEMORY_STORE_OVERHEAD);
                let pages = cap.div_ceil(PAGE_SIZE);
                (
                    usize::try_from(pages.saturating_mul(PAGE_SIZE)).unwrap_or(usize::MAX),
                    StoreOptions {
                        max_bytes,
                        hot_cache_bytes: Some(MEMORY_HOT_CACHE),
                        max_page_count: u32::try_from(pages).ok(),
                        cache_kib: None,
                    },
                )
            }
        };
        Fixed {
            store: store_part,
            caches: usize::try_from(options.hot_cache_fixed_bytes())
                .unwrap_or(usize::MAX)
                .saturating_add(gateway.cache_capacity()),
            options,
        }
    }

    pub fn total(&self) -> usize {
        self.store.saturating_add(self.caches)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_designs_figures() {
        let gateway = GatewayConfig::default();
        // A private instance: 36 + 4 + 2 + 1.
        let private = Fixed::of(
            Store::Memory {
                max_bytes: 32 << 20,
            },
            &gateway,
        );
        assert_eq!(private.store, 36 << 20);
        assert_eq!(private.total(), 43 << 20);
        assert_eq!(private.options.max_page_count, Some(9216));
        assert_eq!(private.options.hot_cache_bytes, Some(4 << 20));
        // The persistent one: 8 + 16 + 2 + 1.
        let persistent = Fixed::of(
            Store::Disk {
                max_bytes: 256 << 20,
            },
            &gateway,
        );
        assert_eq!(persistent.total(), 27 << 20);
        assert_eq!(persistent.options.cache_kib, Some(8192));
        // Eight private instances and the writer fit the ephemeral budget,
        // as one persistent instance and the writer fit the persistent one.
        assert!(8 * private.total() + WRITER_DATA_CAP <= EPHEMERAL_MEMORY);
        assert!(persistent.total() + WRITER_DATA_CAP <= PERSISTENT_MEMORY);
    }

    /// Review of #141, m3: a tiny disk target's hot cache still holds its
    /// own structures, and the figure is the opened store's.
    #[test]
    fn a_tiny_hot_cache_is_counted_as_upstream_opens_it() {
        let gateway = GatewayConfig::default();
        for max_bytes in [0, 1, 4096, 16 << 20, 1 << 30] {
            let fixed = Fixed::of(Store::Disk { max_bytes }, &gateway);
            let dir = tempfile::tempdir().unwrap();
            let store = freedom_ipfs_store::SqliteBlockStore::open_with(
                dir.path().join("store.sqlite3"),
                fixed.options,
            )
            .unwrap();
            assert_eq!(
                fixed.caches,
                store.hot_cache_capacity() as usize + gateway.cache_capacity(),
                "{max_bytes}"
            );
            assert!(store.close(std::time::Duration::from_secs(2)));
        }
    }
}
