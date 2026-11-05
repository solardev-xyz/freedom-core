//! Memory a walk holds, together with its charge (design 0009, Bounds: a
//! request's memory is reserved before it is allocated, and released once
//! it is gone).
//!
//! [`Charged`] keeps a value with the bytes of the request's memory charged
//! for it. Only this module changes a charge, and nothing outside it can
//! name a new one for a value it already holds:
//! - a charge is set as its value is made or arrives: reserved before it is
//!   made ([`Charged::make`], [`Charged::room`]), or already held by the
//!   machine ([`Charged::arrived`]);
//! - it changes only as this module measures the value ([`Measured`]),
//!   after the change: [`Charged::remake`] and [`Charged::keep`] hold what
//!   it grew by, or release what has gone after it went;
//! - it goes only by consuming the value: [`Charged::release`] drops the
//!   value first, then releases its charge.
//!
//! Moving the bytes to another holder is one step that keeps the charge:
//! [`Charged::map`] and [`Charged::join`] within the walk, and the core's
//! [`super::Core::hash_charged`], [`super::Core::body_charged`] and
//! [`super::Core::head_charged`] out of it ([`Charged::hand_over`]), where
//! the new holder has the value before the walk's charge goes.
//!
//! The walk's holding itself is [`Held`], whose count only this module
//! writes. The raw hold and release ([`super::Holding`]) are the
//! machine's; neither walk imports them, and with the probe any release
//! that leaves a live value uncovered is caught at that release.
//!
//! What the type can't follow is a value a closure takes out of its
//! `Charged` and keeps elsewhere, or memory never charged at all: the
//! allocator probe in the tests covers those.
//!
//! A value dropped without its release, as a walk's are when the request
//! ends, leaves its charge held: more than what is live, never less.
//!
//! With the `memory-probe` feature, a ledger beside the count adds up what
//! the live values are charged. Every release checks that the walk still
//! holds that much, a value measured past its charge counts as memory past
//! the count, and each input ends with the walk's holding equal to the
//! ledger ([`super::Verifier::over_released`]).

use std::collections::VecDeque;

use fc_swarm::manifest::{self, Lookup};

use super::ant::Entry;
use super::ipfs::{self, Hamt, Need};
use super::{Core, Holding};

/// A value the walk holds and the bytes charged for it.
#[derive(Debug)]
#[must_use = "a charged value goes with `release`, or moves on with its charge"]
pub(crate) struct Charged<T> {
    value: T,
    cost: usize,
    tally: Tally,
}

impl<T> Charged<T> {
    /// A value that came in with its cost already in the walk's holding: a
    /// piece's bytes or a job's work, which the machine holds as they
    /// arrive.
    pub(crate) fn arrived<X>(core: &Core<X>, value: T, cost: usize) -> Self {
        Self {
            value,
            cost,
            tally: Tally::new(core, cost),
        }
    }

    /// `value`, just made within room the walk holds or checked, charged
    /// `cost`.
    pub(crate) fn new<X: Copy>(core: &mut Core<X>, value: T, cost: usize) -> Self {
        core.hold(cost);
        Self::arrived(core, value, cost)
    }

    /// The value `make` gives, its `cost` reserved before it is made:
    /// `None`, and nothing made, when it doesn't fit.
    pub(crate) fn make<X: Copy>(
        core: &mut Core<X>,
        cost: usize,
        make: impl FnOnce() -> T,
    ) -> Option<Self> {
        if !core.fits(cost) {
            return None;
        }
        core.hold(cost);
        Some(Self::arrived(core, make(), cost))
    }

    pub(crate) fn cost(&self) -> usize {
        self.cost
    }

    /// The value, to change in place without growing past its charge.
    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// `room` joins the value's charge, for what the value is to grow by
    /// in place ([`Charged::get_mut`], [`Charged::change`]).
    pub(crate) fn absorb(&mut self, room: Charged<()>) {
        let Charged { cost, tally, .. } = room;
        self.cost += cost;
        self.tally.absorb(tally);
    }

    /// The value goes, then its charge.
    pub(crate) fn release<X: Copy>(self, core: &mut Core<X>) {
        let Self { value, cost, tally } = self;
        drop(value);
        tally.done();
        core.unhold(cost);
    }

    /// The value becomes what `f` makes of it, under the same charge: what
    /// `f` keeps, makes or drops of it stays covered until the value goes,
    /// moves on, or is measured again ([`Charged::remake`]).
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Charged<U> {
        let Self { value, cost, tally } = self;
        Charged {
            value: f(value),
            cost,
            tally,
        }
    }

    /// The value becomes what `f` makes of it, charged what that holds as
    /// this module measures it ([`Measured`]). What `f` dropped or shrank
    /// has gone by then, and its charge goes after it. A value that holds
    /// more than the charge grew without room reserved for it: it is
    /// charged the rest at once, and with the probe that is memory past the
    /// count.
    pub(crate) fn remake<U: Measured, X: Copy>(
        self,
        core: &mut Core<X>,
        f: impl FnOnce(T) -> U,
    ) -> Charged<U> {
        let mut made = self.map(f);
        let cost = made.value.held();
        made.set_cost(core, cost);
        made
    }

    /// [`Charged::map`], where `f` may find nothing: then its charge goes,
    /// after the value.
    pub(crate) fn try_map<U, X: Copy>(
        self,
        core: &mut Core<X>,
        f: impl FnOnce(T) -> Option<U>,
    ) -> Option<Charged<U>> {
        let Self { value, cost, tally } = self;
        match f(value) {
            Some(value) => Some(Charged { value, cost, tally }),
            None => {
                tally.done();
                core.unhold(cost);
                None
            }
        }
    }

    /// Two values under their two charges together.
    pub(crate) fn join<U>(self, other: Charged<U>) -> Charged<(T, U)> {
        let Self { value, cost, tally } = self;
        let Charged {
            value: other,
            cost: more,
            tally: more_tally,
        } = other;
        Charged {
            value: (value, other),
            cost: cost + more,
            tally: tally.join(more_tally),
        }
    }

    /// The value moves on to a holder that counts it itself (a job, the
    /// body's queue, the head): `take` gives it over, and the walk's charge
    /// goes after.
    pub(super) fn hand_over<X: Copy>(self, core: &mut Core<X>, take: impl FnOnce(&mut Core<X>, T)) {
        let Self { value, cost, tally } = self;
        take(core, value);
        tally.done();
        core.unhold(cost);
    }

    /// The charge becomes `cost`: more is held first, or what the value no
    /// longer holds, which has gone, is released. Only a measure of the
    /// value, taken here, sets it.
    fn set_cost<X: Copy>(&mut self, core: &mut Core<X>, cost: usize) {
        if cost > self.cost {
            let more = cost - self.cost;
            #[cfg(feature = "memory-probe")]
            core.walk_held.fault(more);
            core.hold(more);
            self.tally.set(cost);
        } else {
            let less = self.cost - cost;
            self.tally.set(cost);
            core.unhold(less);
        }
        self.cost = cost;
    }
}

impl<T: Measured> Charged<T> {
    /// `value`, just made, charged what it holds.
    pub(crate) fn measured<X: Copy>(core: &mut Core<X>, value: T) -> Self {
        let cost = value.held();
        Self::new(core, value, cost)
    }

    /// A value that holds nothing yet (an empty buffer, path or queue),
    /// charged nothing: what it is to hold comes with room joined to it
    /// ([`Charged::absorb`]).
    pub(crate) fn nothing<X>(core: &Core<X>) -> Self
    where
        T: Default,
    {
        let value = T::default();
        debug_assert_eq!(value.held(), 0);
        Self::arrived(core, value, 0)
    }

    /// The value changed in place by `f`, then charged what it holds as
    /// this module measures it, as [`Charged::remake`] does: what it gave
    /// back is released after it went, and what it grew by past its charge
    /// is memory past the count.
    pub(crate) fn change<X: Copy>(&mut self, core: &mut Core<X>, f: impl FnOnce(&mut T)) {
        f(&mut self.value);
        let cost = self.value.held();
        self.set_cost(core, cost);
    }
}

impl Charged<()> {
    /// Room for what is to be made: `None` when it doesn't fit.
    pub(crate) fn room<X: Copy>(core: &mut Core<X>, n: usize) -> Option<Self> {
        Self::make(core, n, || ())
    }

    /// `n` of this room's charge, as a room of its own (all of it, at most).
    pub(crate) fn split(&mut self, n: usize) -> Self {
        let n = n.min(self.cost);
        self.cost -= n;
        let tally = self.tally.split(n);
        Self {
            value: (),
            cost: n,
            tally,
        }
    }
}

impl Charged<Vec<u8>> {
    /// Appends what fits in the charge from `src`, without growing past it:
    /// how much it took. A buffer made with its charge as its capacity
    /// never reallocates.
    pub(crate) fn fill_from(&mut self, src: &[u8]) -> usize {
        let n = src.len().min(self.cost.saturating_sub(self.value.len()));
        self.value.extend_from_slice(&src[..n]);
        n
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.value
    }

    /// The charge past the buffer's bytes, as a room of its own: what a
    /// buffer longer than its block holds past it, which stays with the
    /// walk while the bytes go to a holder that counts their length only
    /// (a hash job). The two together still cover the buffer.
    pub(crate) fn spare(&mut self) -> Charged<()> {
        let n = self.cost.saturating_sub(self.value.len());
        self.cost -= n;
        let tally = self.tally.split(n);
        Charged {
            value: (),
            cost: n,
            tally,
        }
    }

    /// Only bytes `from..to` stay (those it has), cut in place and the
    /// buffer shrunk to them; then the charge of what went is released.
    pub(crate) fn keep<X: Copy>(self, core: &mut Core<X>, from: usize, to: usize) -> Self {
        self.remake(core, |mut v| {
            v.truncate(to);
            v.drain(..from.min(v.len()));
            v.shrink_to_fit();
            v
        })
    }
}

impl<A, E: Copy> Charged<Result<A, E>> {
    /// A result's value under the charge, or its error (which holds
    /// nothing) with the charge released.
    pub(crate) fn transpose<X: Copy>(self, core: &mut Core<X>) -> Result<Charged<A>, E> {
        let Self { value, cost, tally } = self;
        match value {
            Ok(value) => Ok(Charged { value, cost, tally }),
            Err(e) => {
                tally.done();
                core.unhold(cost);
                Err(e)
            }
        }
    }
}

impl<T> std::ops::Deref for Charged<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

/// What a value holds on the heap, as its charge counts it. The measures
/// are this module's: the trait is sealed, so a walk can't give a value a
/// measure of its own (nothing, say) to lower a live value's charge.
pub(crate) trait Measured: sealed::Sealed {
    fn held(&self) -> usize;
}

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for Vec<u8> {}

impl Measured for Vec<u8> {
    /// Its whole buffer: what it has room for, not only what it has.
    fn held(&self) -> usize {
        self.capacity()
    }
}

impl sealed::Sealed for Box<Lookup> {}

impl Measured for Box<Lookup> {
    /// The box, and what the lookup holds.
    fn held(&self) -> usize {
        std::mem::size_of::<Lookup>() + Lookup::held(self)
    }
}

impl sealed::Sealed for manifest::Node {}

impl Measured for manifest::Node {
    fn held(&self) -> usize {
        self.cost()
    }
}

impl sealed::Sealed for Entry {}

impl Measured for Entry {
    /// Its strings; the rest is inline.
    fn held(&self) -> usize {
        self.content_type.as_ref().map_or(0, String::capacity)
            + self.filename.as_ref().map_or(0, String::capacity)
    }
}

impl sealed::Sealed for String {}

impl Measured for String {
    /// Its whole buffer, as a byte buffer's.
    fn held(&self) -> usize {
        self.capacity()
    }
}

impl sealed::Sealed for Vec<String> {}

impl Measured for Vec<String> {
    /// Its strings and its slots.
    fn held(&self) -> usize {
        self.iter().map(String::capacity).sum::<usize>()
            + self.capacity() * std::mem::size_of::<String>()
    }
}

impl sealed::Sealed for VecDeque<Need> {}

impl Measured for VecDeque<Need> {
    /// Its slots: the needs' CIDs are charged together beside it.
    fn held(&self) -> usize {
        self.capacity() * std::mem::size_of::<Need>()
    }
}

impl sealed::Sealed for Hamt {}

impl Measured for Hamt {
    /// Its root's CID, and each shard's CID and block with its map entry.
    fn held(&self) -> usize {
        self.root.capacity()
            + self
                .shards
                .iter()
                .map(|(cid, block)| cid.capacity() + block.capacity() + ipfs::MAP_ENTRY)
                .sum::<usize>()
    }
}

impl<T: Measured> sealed::Sealed for Option<T> {}

impl<T: Measured> Measured for Option<T> {
    fn held(&self) -> usize {
        self.as_ref().map_or(0, T::held)
    }
}

impl<A: Measured, B: Measured> sealed::Sealed for (A, B) {}

impl<A: Measured, B: Measured> Measured for (A, B) {
    fn held(&self) -> usize {
        self.0.held() + self.1.held()
    }
}

impl<A: Measured, E: Copy> sealed::Sealed for Result<A, E> {}

impl<A: Measured, E: Copy> Measured for Result<A, E> {
    /// The value's, or nothing for an error, which is `Copy` and so owns
    /// no heap.
    fn held(&self) -> usize {
        self.as_ref().map_or(0, A::held)
    }
}

/// The walk's holding: what it has taken in and not yet released, by
/// count. The count is this module's, so nothing else writes it: the core
/// changes it only by [`Held::add`] and [`Held::take`] (its
/// [`super::Holding`]), and with the probe every take checks that what is
/// left still covers what the live [`Charged`] values are charged.
#[derive(Debug, Default)]
pub(crate) struct Held {
    n: usize,
    /// Releases without their hold and, with the probe, memory past the
    /// count ([`super::Verifier::over_released`]).
    faults: usize,
    /// What the walk's live [`Charged`] values are charged.
    #[cfg(feature = "memory-probe")]
    ledger: Ledger,
}

impl Held {
    pub(super) fn get(&self) -> usize {
        self.n
    }

    pub(super) fn faults(&self) -> usize {
        self.faults
    }

    pub(super) fn add(&mut self, n: usize) {
        self.n += n;
    }

    /// `n` bytes go, once what they covered has gone. More than it holds,
    /// while the walk runs, is a release without its hold: counted, and
    /// never taken below zero.
    pub(super) fn take(&mut self, n: usize, running: bool) {
        if n > self.n && running {
            self.faults = self.faults.saturating_add(n - self.n);
        }
        self.n = self.n.saturating_sub(n);
        self.check_live();
    }

    /// All of it goes at once, at the request's end: nothing it charged may
    /// still be live.
    pub(super) fn clear(&mut self) {
        self.n = 0;
        self.check_live();
    }

    /// After an input (each walk's memory is all [`Charged`]): what it
    /// holds is what its live values are charged, no less (memory past the
    /// count) and no more (a charge whose value went without it).
    pub(super) fn audit(&mut self) {
        #[cfg(feature = "memory-probe")]
        {
            let live = self.ledger.live();
            if live != self.n {
                self.fault(live.abs_diff(self.n));
            }
        }
    }

    /// After a release: the live [`Charged`] values are still covered. One
    /// the walk still has once its charge has gone is memory past the
    /// request's count.
    fn check_live(&mut self) {
        #[cfg(feature = "memory-probe")]
        {
            let live = self.ledger.live();
            if live > self.n {
                self.fault(live - self.n);
            }
        }
    }

    /// Memory the walk holds that its charges don't match: counted with
    /// the releases that had no hold, as the same fault.
    #[cfg(feature = "memory-probe")]
    fn fault(&mut self, n: usize) {
        self.faults = self.faults.saturating_add(n.max(1));
    }
}

#[cfg(feature = "memory-probe")]
use ledger::{Ledger, Tally};
#[cfg(not(feature = "memory-probe"))]
use none::Tally;

/// What the live values are charged, counted beside the core.
#[cfg(feature = "memory-probe")]
mod ledger {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::Core;

    /// The request's count of what its live [`super::Charged`] values are
    /// charged.
    #[derive(Debug, Default)]
    pub(super) struct Ledger(Arc<AtomicUsize>);

    impl Ledger {
        pub(super) fn live(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }
    }

    /// One value's part of the ledger, which goes when the value does.
    #[derive(Debug)]
    pub(super) struct Tally {
        ledger: Arc<AtomicUsize>,
        n: usize,
    }

    impl Tally {
        pub(super) fn new<X>(core: &Core<X>, n: usize) -> Self {
            let ledger = Arc::clone(&core.walk_held.ledger.0);
            ledger.fetch_add(n, Ordering::Relaxed);
            Self { ledger, n }
        }

        pub(super) fn set(&mut self, n: usize) {
            if n > self.n {
                self.ledger.fetch_add(n - self.n, Ordering::Relaxed);
            } else {
                self.ledger.fetch_sub(self.n - n, Ordering::Relaxed);
            }
            self.n = n;
        }

        pub(super) fn join(mut self, other: Tally) -> Tally {
            self.absorb(other);
            self
        }

        pub(super) fn absorb(&mut self, mut other: Tally) {
            self.n += std::mem::take(&mut other.n);
        }

        pub(super) fn split(&mut self, n: usize) -> Tally {
            self.n -= n;
            Tally {
                ledger: Arc::clone(&self.ledger),
                n,
            }
        }

        /// Its part of the ledger goes: the value has gone, or has moved
        /// to a holder of its own.
        pub(super) fn done(self) {}
    }

    impl Drop for Tally {
        fn drop(&mut self) {
            self.ledger.fetch_sub(self.n, Ordering::Relaxed);
        }
    }
}

/// Without the probe, nothing is counted.
#[cfg(not(feature = "memory-probe"))]
mod none {
    use super::super::Core;

    #[derive(Debug)]
    pub(super) struct Tally;

    impl Tally {
        pub(super) fn new<X>(_core: &Core<X>, _n: usize) -> Self {
            Self
        }

        pub(super) fn set(&mut self, _n: usize) {}

        pub(super) fn join(self, _other: Tally) -> Tally {
            self
        }

        pub(super) fn absorb(&mut self, _other: Tally) {}

        pub(super) fn split(&mut self, _n: usize) -> Tally {
            Self
        }

        pub(super) fn done(self) {}
    }
}

/// What a walk can't write at all, the compiler refuses: a charge set by
/// hand (`set_cost` is private, E0624), and the holding's count written
/// directly (`Held`'s field is private, E0616). These check what is left.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::plan::Node;

    fn core() -> Core<()> {
        Core::new(0, Node::Ant, false, None, 1 << 20)
    }

    /// A wire made within its charge, 4,104 bytes as a chunk's is.
    fn wire(core: &mut Core<()>) -> Charged<Vec<u8>> {
        Charged::make(core, 4104, || vec![7; 4104]).unwrap()
    }

    #[test]
    fn a_measure_is_the_buffer_not_its_length() {
        let mut core = core();
        // Emptied but not shrunk: the buffer is still there, and so is its
        // charge.
        let cleared = wire(&mut core).remake(&mut core, |mut w| {
            w.clear();
            w
        });
        assert_eq!(cleared.cost(), 4104);
        assert_eq!(core.walk_held.get(), 4104);
        cleared.release(&mut core);
        // Cut and shrunk: what went is released after it went.
        let kept = wire(&mut core).keep(&mut core, 8, 18);
        assert_eq!(&**kept, &[7; 10]);
        assert_eq!(kept.cost(), kept.capacity());
        assert_eq!(core.walk_held.get(), kept.cost());
        kept.release(&mut core);
        assert_eq!(core.walk_held.get(), 0);
        assert_eq!(core.walk_held.faults(), 0);
    }

    #[test]
    fn a_hand_over_has_the_value_go_before_the_charge() {
        let mut core = core();
        let mut taken = 0;
        wire(&mut core).hand_over(&mut core, |core, w| {
            assert_eq!(core.walk_held.get(), 4104);
            taken = w.len();
        });
        assert_eq!(taken, 4104);
        assert_eq!(core.walk_held.get(), 0);
        assert_eq!(core.walk_held.faults(), 0);
    }

    #[test]
    fn room_joins_a_value_and_its_measure_follows_it() {
        let mut core = core();
        // Nothing yet, then room for what it is to hold, then charged what
        // it holds once it is changed.
        let mut v: Charged<Vec<u8>> = Charged::nothing(&core);
        assert_eq!(v.cost(), 0);
        v.absorb(Charged::room(&mut core, 64).unwrap());
        assert_eq!(v.cost(), 64);
        v.change(&mut core, |v| {
            v.reserve_exact(16);
            v.extend_from_slice(&[1; 16]);
        });
        assert_eq!(v.cost(), v.capacity());
        assert_eq!(core.walk_held.get(), v.cost());
        // A buffer longer than its bytes: the charge past them as a room of
        // its own, the two together the buffer's.
        let mut b = Charged::make(&mut core, 100, || Vec::with_capacity(100)).unwrap();
        b.get_mut().extend_from_slice(&[2; 40]);
        let spare = b.spare();
        assert_eq!((b.cost(), spare.cost()), (40, 60));
        assert_eq!(core.walk_held.get(), v.cost() + 100);
        b.release(&mut core);
        spare.release(&mut core);
        v.release(&mut core);
        assert_eq!(core.walk_held.get(), 0);
        assert_eq!(core.walk_held.faults(), 0);
    }

    /// A value changed past its charge grew before its hold.
    #[cfg(feature = "memory-probe")]
    #[test]
    fn a_change_past_the_charge_is_memory_past_the_count() {
        let mut core = core();
        let mut v: Charged<Vec<u8>> = Charged::nothing(&core);
        v.change(&mut core, |v| v.extend_from_slice(&[0; 32]));
        assert_eq!(core.walk_held.get(), v.cost());
        assert!(core.walk_held.faults() > 0);
        v.release(&mut core);
    }

    /// Round 4's reproduction, as the walk can still write it: the wire's
    /// charge released by the raw count while the wire is live.
    #[cfg(feature = "memory-probe")]
    #[test]
    fn a_release_under_a_live_value_is_caught_at_the_release() {
        let mut core = core();
        let w = wire(&mut core);
        core.walk_held.take(w.cost(), true);
        assert!(core.walk_held.faults() >= 4104);
        drop(w);

        let mut core = self::core();
        let w = wire(&mut core);
        core.unhold(w.cost());
        assert!(core.walk_held.faults() >= 4104);
        drop(w);
    }

    /// A value measured past its charge grew before its hold.
    #[cfg(feature = "memory-probe")]
    #[test]
    fn growth_past_the_charge_is_memory_past_the_count() {
        let mut core = core();
        let grown = wire(&mut core).remake(&mut core, |mut w| {
            w.resize(8192, 0);
            w
        });
        assert_eq!(core.walk_held.get(), grown.cost());
        assert!(core.walk_held.faults() > 0);
        grown.release(&mut core);
    }
}
