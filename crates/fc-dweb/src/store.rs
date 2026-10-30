//! What verified requests share in the dweb thread (design 0009, The
//! structure cache; IPNS and DNSLink): a structure cache and IPNS sequence
//! floors per partition, and the epochs that let `dweb.forget` leave
//! nothing of a partition behind.
//!
//! - **Partitions:** the profile's (`None`), and one per private window,
//!   by its name. A private window has a cache and floors while fewer than
//!   [`PRIVATE_PARTITIONS`] others hold them; past that its requests
//!   fetch every chunk and keep no floor, and no other partition's entries
//!   are touched.
//! - **Isolation:** each partition has its own allowance and its own
//!   least-recently-used order, for its cache and for its floors. No
//!   partition reads, counts against or evicts another's entries, so a
//!   private page can neither time another session's loads nor evict the
//!   profile's floors.
//! - **Epochs:** a request takes a [`Ticket`] when it starts. What its walk
//!   gives back carries the ticket. Once the partition is forgotten, or
//!   made again, the ticket is stale, and what it brings is dropped: a
//!   late piece reply or hashing result leaves no entry behind.
//!
//! The caller (the dweb thread) answers a request's `/chunks/<address>`
//! pieces from [`Store::answer`] before they reach main, keeps the chunks
//! its walk gives back ([`Output::Remember`]) with [`Store::remember`], and
//! checks each record the walk verifies against the floor with
//! [`Store::floor`], in one step.
//!
//! [`Output::Remember`]: crate::verifier::Output::Remember

use std::collections::BTreeMap;

use crate::verifier::PieceRequest;

/// The profile's structure cache: about 2,000 chunks.
pub const PROFILE_CACHE: usize = 8 << 20;
/// A private window's: about 500 chunks.
pub const PRIVATE_CACHE: usize = 2 << 20;
/// Private partitions with a cache and floors at once.
pub const PRIVATE_PARTITIONS: usize = 8;
/// Names with a floor, per partition.
pub const FLOOR_NAMES: usize = 1024;
/// What a cached chunk holds beside its wire: its address and the maps'
/// entries.
const ENTRY_COST: usize = 128;

/// A request's hold on its partition: the partition, and the epoch it
/// started under (none when the partition has no cache or floors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    partition: Option<String>,
    epoch: Option<u64>,
}

impl Ticket {
    /// Whether the request's partition has a cache and floors.
    pub fn shared(&self) -> bool {
        self.epoch.is_some()
    }
}

/// What [`Store::floor`] decided of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorCheck {
    /// At or above the floor, or no floor holds: the floor is now at least
    /// its sequence.
    Accepted,
    /// Below the floor while the floor's record is still valid.
    Refused,
}

/// A name's floor: the highest sequence verified, and when its record's
/// validity ends (Unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Floor {
    sequence: u64,
    valid_until: i64,
}

/// A least-recently-used map with a tick per use.
#[derive(Debug)]
struct Lru<K: Ord + Clone, V> {
    tick: u64,
    entries: BTreeMap<K, (V, u64)>,
    order: BTreeMap<u64, K>,
}

impl<K: Ord + Clone, V> Lru<K, V> {
    fn new() -> Self {
        Self {
            tick: 0,
            entries: BTreeMap::new(),
            order: BTreeMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    /// The value, now the most recently used.
    fn get(&mut self, key: &K) -> Option<&mut V> {
        let (_, used) = self.entries.get(key)?;
        let old = *used;
        self.tick += 1;
        let now = self.tick;
        self.order.remove(&old);
        self.order.insert(now, key.clone());
        let (v, used) = self.entries.get_mut(key)?;
        *used = now;
        Some(v)
    }

    fn insert(&mut self, key: K, value: V) {
        self.tick += 1;
        if let Some((_, old)) = self.entries.insert(key.clone(), (value, self.tick)) {
            self.order.remove(&old);
        }
        self.order.insert(self.tick, key);
    }

    /// The least recently used entry, taken out.
    fn pop_oldest(&mut self) -> Option<(K, V)> {
        let (_, key) = self.order.pop_first()?;
        let (v, _) = self.entries.remove(&key)?;
        Some((key, v))
    }
}

#[derive(Debug)]
struct Partition {
    epoch: u64,
    allowance: usize,
    held: usize,
    chunks: Lru<[u8; 32], Vec<u8>>,
    floors: Lru<Vec<u8>, Floor>,
}

impl Partition {
    fn new(epoch: u64, allowance: usize) -> Self {
        Self {
            epoch,
            allowance,
            held: 0,
            chunks: Lru::new(),
            floors: Lru::new(),
        }
    }
}

/// The structure caches and IPNS floors of every partition.
#[derive(Debug)]
pub struct Store {
    profile: Partition,
    private: BTreeMap<String, Partition>,
    next_epoch: u64,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

/// The address a `/chunks/<64 hex>` piece asks for.
fn chunk_address(piece: &PieceRequest) -> Option<[u8; 32]> {
    let hex = piece.path.strip_prefix("/chunks/")?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        let digit = |c: u8| char::from(c).to_digit(16);
        let (Some(h), Some(l)) = (digit(pair[0]), digit(pair[1])) else {
            return None;
        };
        out[i] = (h * 16 + l) as u8;
    }
    Some(out)
}

impl Store {
    pub fn new() -> Self {
        Self {
            profile: Partition::new(0, PROFILE_CACHE),
            private: BTreeMap::new(),
            next_epoch: 1,
        }
    }

    /// A request starts in `partition` (`None`: the profile's): its
    /// ticket. A private partition gets its cache and floors here, when
    /// fewer than [`PRIVATE_PARTITIONS`] others hold them.
    pub fn begin(&mut self, partition: Option<&str>) -> Ticket {
        let Some(name) = partition else {
            return Ticket {
                partition: None,
                epoch: Some(self.profile.epoch),
            };
        };
        let epoch = match self.private.get(name) {
            Some(p) => Some(p.epoch),
            None if self.private.len() < PRIVATE_PARTITIONS => {
                let epoch = self.next_epoch;
                self.next_epoch += 1;
                self.private
                    .insert(name.to_owned(), Partition::new(epoch, PRIVATE_CACHE));
                Some(epoch)
            }
            None => None,
        };
        Ticket {
            partition: Some(name.to_owned()),
            epoch,
        }
    }

    /// The ticket's partition, while the ticket is current.
    fn current(&mut self, t: &Ticket) -> Option<&mut Partition> {
        let epoch = t.epoch?;
        let p = match &t.partition {
            None => &mut self.profile,
            Some(name) => self.private.get_mut(name)?,
        };
        (p.epoch == epoch).then_some(p)
    }

    /// The whole answer to a piece the request asks for, from its
    /// partition's cache: a `/chunks/<address>` piece whose chunk is held.
    pub fn answer(&mut self, t: &Ticket, piece: &PieceRequest) -> Option<Vec<u8>> {
        if piece.stream {
            return None;
        }
        let address = chunk_address(piece)?;
        let p = self.current(t)?;
        p.chunks.get(&address).cloned()
    }

    /// A verified structure chunk the request's walk gave back: kept in
    /// the partition's cache, its least recently used entries evicted past
    /// its allowance. Dropped when the ticket is stale.
    pub fn remember(&mut self, t: &Ticket, address: [u8; 32], wire: Vec<u8>) {
        let Some(p) = self.current(t) else {
            return;
        };
        if p.chunks.get(&address).is_some() {
            return;
        }
        let cost = wire.len() + ENTRY_COST;
        if cost > p.allowance {
            return;
        }
        p.held += cost;
        p.chunks.insert(address, wire);
        while p.held > p.allowance {
            let Some((_, w)) = p.chunks.pop_oldest() else {
                break;
            };
            p.held = p.held.saturating_sub(w.len() + ENTRY_COST);
        }
    }

    /// A record of `name` (its CID's bytes) passed with `sequence`, valid
    /// until `valid_until` (Unix seconds), at `now`. Below the partition's
    /// floor for the name while the floor's record is still valid, it is
    /// refused; otherwise it is accepted, and the floor rises to it. One
    /// step, so the floor only rises, and only records checked after a rise
    /// are held to it. A stale ticket, or a partition without floors,
    /// accepts and keeps nothing.
    pub fn floor(
        &mut self,
        t: &Ticket,
        name: &[u8],
        sequence: u64,
        valid_until: i64,
        now: i64,
    ) -> FloorCheck {
        let Some(p) = self.current(t) else {
            return FloorCheck::Accepted;
        };
        let key = name.to_vec();
        let next = Floor {
            sequence,
            valid_until,
        };
        if let Some(f) = p.floors.get(&key) {
            if f.valid_until > now {
                if sequence < f.sequence {
                    return FloorCheck::Refused;
                }
                if sequence == f.sequence {
                    f.valid_until = f.valid_until.max(valid_until);
                } else {
                    *f = next;
                }
            } else {
                // The floor's record has expired: it holds nothing back.
                *f = next;
            }
            return FloorCheck::Accepted;
        }
        p.floors.insert(key, next);
        while p.floors.len() > FLOOR_NAMES {
            p.floors.pop_oldest();
        }
        FloorCheck::Accepted
    }

    /// `dweb.forget`: the partition's cache and floors go, and any ticket
    /// taken before is stale. The profile's partition starts empty again;
    /// a private one gives up its place.
    pub fn forget(&mut self, partition: Option<&str>) {
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        match partition {
            None => self.profile = Partition::new(epoch, PROFILE_CACHE),
            Some(name) => {
                self.private.remove(name);
            }
        }
    }

    /// What the caches hold, all partitions together (at most the
    /// profile's allowance and [`PRIVATE_PARTITIONS`] private ones).
    pub fn cached(&self) -> usize {
        self.profile.held + self.private.values().map(|p| p.held).sum::<usize>()
    }

    /// Chunks the partition's cache holds.
    pub fn chunks(&self, partition: Option<&str>) -> usize {
        match partition {
            None => self.profile.chunks.len(),
            Some(name) => self.private.get(name).map_or(0, |p| p.chunks.len()),
        }
    }

    /// Names the partition holds a floor for.
    pub fn floors(&self, partition: Option<&str>) -> usize {
        match partition {
            None => self.profile.floors.len(),
            Some(name) => self.private.get(name).map_or(0, |p| p.floors.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::PieceId;

    fn piece(address: [u8; 32]) -> PieceRequest {
        let hex: String = address.iter().map(|b| format!("{b:02x}")).collect();
        PieceRequest {
            id: PieceId(0),
            path: format!("/chunks/{hex}"),
            headers: vec![],
            stream: false,
            max_bytes: Some(4104),
        }
    }

    fn addr(i: u32) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[..4].copy_from_slice(&i.to_be_bytes());
        a
    }

    #[test]
    fn partitions_share_nothing() {
        let mut s = Store::new();
        let profile = s.begin(None);
        let a = s.begin(Some("a"));
        let b = s.begin(Some("b"));
        s.remember(&profile, addr(1), vec![1; 4104]);
        s.remember(&a, addr(2), vec![2; 4104]);
        // Each reads only its own.
        assert_eq!(s.answer(&profile, &piece(addr(1))), Some(vec![1; 4104]));
        assert_eq!(s.answer(&a, &piece(addr(1))), None);
        assert_eq!(s.answer(&b, &piece(addr(1))), None);
        assert_eq!(s.answer(&b, &piece(addr(2))), None);
        assert_eq!(s.answer(&a, &piece(addr(2))), Some(vec![2; 4104]));
        // A stream is never answered from the cache.
        let mut p = piece(addr(1));
        p.stream = true;
        assert_eq!(s.answer(&profile, &p), None);
    }

    #[test]
    fn a_partition_evicts_only_its_own() {
        let mut s = Store::new();
        let profile = s.begin(None);
        let a = s.begin(Some("a"));
        s.remember(&profile, addr(0), vec![0; 4104]);
        // Fill a's 2 MiB past its allowance.
        for i in 1..=600 {
            s.remember(&a, addr(i), vec![0; 4104]);
        }
        assert!(s.chunks(Some("a")) < 600);
        assert!(s.cached() <= PROFILE_CACHE + PRIVATE_CACHE);
        // The oldest of a's went; the profile's is untouched.
        assert_eq!(s.answer(&a, &piece(addr(1))), None);
        assert!(s.answer(&a, &piece(addr(600))).is_some());
        assert!(s.answer(&profile, &piece(addr(0))).is_some());
        // A use makes an entry the newest.
        let kept = 600 - s.chunks(Some("a")) as u32 + 1;
        assert!(s.answer(&a, &piece(addr(kept))).is_some());
        s.remember(&a, addr(601), vec![0; 4104]);
        assert!(s.answer(&a, &piece(addr(kept))).is_some());
        assert_eq!(s.answer(&a, &piece(addr(kept + 1))), None);
    }

    #[test]
    fn a_ninth_private_partition_has_no_cache() {
        let mut s = Store::new();
        let tickets: Vec<_> = (0..9).map(|i| s.begin(Some(&format!("w{i}")))).collect();
        assert!(tickets[..8].iter().all(Ticket::shared));
        assert!(!tickets[8].shared());
        s.remember(&tickets[8], addr(1), vec![0; 4104]);
        assert_eq!(s.answer(&tickets[8], &piece(addr(1))), None);
        assert_eq!(s.cached(), 0);
        // One closes: the next request of the ninth gets its place.
        s.forget(Some("w0"));
        let late = s.begin(Some("w8"));
        assert!(late.shared());
        s.remember(&late, addr(1), vec![0; 4104]);
        assert!(s.answer(&late, &piece(addr(1))).is_some());
    }

    #[test]
    fn forget_leaves_nothing_and_late_results_none() {
        let mut s = Store::new();
        let t = s.begin(Some("a"));
        s.remember(&t, addr(1), vec![0; 4104]);
        assert_eq!(s.floor(&t, b"name", 5, 100, 0), FloorCheck::Accepted);
        s.forget(Some("a"));
        assert_eq!((s.chunks(Some("a")), s.floors(Some("a"))), (0, 0));
        // The old request's late results: no entry, no floor.
        s.remember(&t, addr(2), vec![0; 4104]);
        assert_eq!(s.floor(&t, b"name", 7, 100, 0), FloorCheck::Accepted);
        assert_eq!(s.cached(), 0);
        // Even once the partition is made again under the same name.
        let again = s.begin(Some("a"));
        s.remember(&t, addr(3), vec![0; 4104]);
        assert_eq!(s.floor(&t, b"name", 9, 100, 0), FloorCheck::Accepted);
        assert_eq!((s.chunks(Some("a")), s.floors(Some("a"))), (0, 0));
        assert_eq!(s.floor(&again, b"name", 3, 100, 0), FloorCheck::Accepted);
        // The profile's forget empties it too.
        let p = s.begin(None);
        s.remember(&p, addr(4), vec![0; 4104]);
        s.forget(None);
        s.remember(&p, addr(5), vec![0; 4104]);
        assert_eq!(s.chunks(None), 0);
    }

    #[test]
    fn floors_rise_and_hold_while_valid() {
        let mut s = Store::new();
        let t = s.begin(None);
        let other = s.begin(Some("a"));
        assert_eq!(s.floor(&t, b"n", 5, 100, 0), FloorCheck::Accepted);
        // Below the floor, while its record is valid: refused.
        assert_eq!(s.floor(&t, b"n", 3, 200, 10), FloorCheck::Refused);
        // Another partition holds no floor for it.
        assert_eq!(s.floor(&other, b"n", 3, 200, 10), FloorCheck::Accepted);
        // At it, and above: accepted, and it rises.
        assert_eq!(s.floor(&t, b"n", 5, 150, 10), FloorCheck::Accepted);
        assert_eq!(s.floor(&t, b"n", 6, 120, 10), FloorCheck::Accepted);
        assert_eq!(s.floor(&t, b"n", 5, 300, 10), FloorCheck::Refused);
        // Once the floor's record has expired, it holds nothing back.
        assert_eq!(s.floor(&t, b"n", 4, 300, 120), FloorCheck::Accepted);
        assert_eq!(s.floor(&t, b"n", 3, 300, 130), FloorCheck::Refused);
    }

    #[test]
    fn floors_are_bounded_per_partition() {
        let mut s = Store::new();
        let profile = s.begin(None);
        let private = s.begin(Some("a"));
        assert_eq!(s.floor(&profile, b"kept", 5, 100, 0), FloorCheck::Accepted);
        // A private page's names never evict the profile's floors.
        for i in 0..2 * FLOOR_NAMES {
            let name = format!("p{i}");
            s.floor(&private, name.as_bytes(), 1, 100, 0);
        }
        assert_eq!(s.floors(Some("a")), FLOOR_NAMES);
        assert_eq!(s.floor(&profile, b"kept", 3, 100, 0), FloorCheck::Refused);
        // Within the profile, its least recently used name goes first.
        for i in 0..FLOOR_NAMES {
            let name = format!("q{i}");
            s.floor(&profile, name.as_bytes(), 1, 100, 0);
        }
        assert_eq!(s.floors(None), FLOOR_NAMES);
        assert_eq!(s.floor(&profile, b"kept", 3, 100, 0), FloorCheck::Accepted);
    }
}
