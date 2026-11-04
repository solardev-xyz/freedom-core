//! Memory a walk holds, together with its charge (design 0009, Bounds: a
//! request's memory is reserved before it is allocated, and released once
//! it is gone).
//!
//! [`Charged`] keeps a value with the bytes of the request's memory charged
//! for it, and the charge goes only by consuming the value:
//! [`Charged::release`] drops the value first, then releases its charge.
//! Moving the bytes to another holder is one step that keeps the charge:
//! [`Charged::map`] and [`Charged::join`] within the walk, and the core's
//! [`super::Core::hash_charged`], [`super::Core::body_charged`] and
//! [`super::Core::head_charged`] out of it, which take the charge over
//! before the walk's goes. A walk that holds its memory only this way can't
//! write a release that comes before its memory has gone: the Swarm walk
//! doesn't import [`super::Holding`], the raw hold and release.
//!
//! A value dropped without its release, as a walk's are when the request
//! ends, leaves its charge held: more than what is live, never less.
//!
//! With the `memory-probe` feature, a ledger beside the core counts what
//! the live values are charged. Every release checks that the walk still
//! holds that much, and each input ends with the Swarm walk's holding equal
//! to it ([`super::Verifier::over_released`]).

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

    /// The value goes, then its charge.
    pub(crate) fn release<X: Copy>(self, core: &mut Core<X>) {
        let Self { value, cost, tally } = self;
        drop(value);
        tally.done();
        core.unhold(cost);
    }

    /// The value becomes what `f` makes of it, under the same charge: what
    /// `f` keeps, makes or drops of it is covered until the charge is
    /// measured again ([`Charged::recharge`]).
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Charged<U> {
        let Self { value, cost, tally } = self;
        Charged {
            value: f(value),
            cost,
            tally,
        }
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

    /// The charge becomes `cost`, what the value holds now: more is held
    /// first, or what it no longer holds, which has gone, is released.
    pub(crate) fn recharge<X: Copy>(&mut self, core: &mut Core<X>, cost: usize) {
        if cost > self.cost {
            core.hold(cost - self.cost);
            self.tally.set(cost);
        } else {
            let less = self.cost - cost;
            self.tally.set(cost);
            core.unhold(less);
        }
        self.cost = cost;
    }

    /// The value and its charge apart, for the core moving them on: the
    /// tally goes once the charge's new holder has it.
    pub(super) fn into_parts(self) -> (T, usize, Tally) {
        (self.value, self.cost, self.tally)
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

#[cfg(feature = "memory-probe")]
pub(crate) use ledger::{Ledger, Tally};
#[cfg(not(feature = "memory-probe"))]
pub(crate) use none::Tally;

/// What the live values are charged, counted beside the core.
#[cfg(feature = "memory-probe")]
mod ledger {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::Core;

    /// The request's count of what its live [`super::Charged`] values are
    /// charged.
    #[derive(Debug, Default)]
    pub(crate) struct Ledger(Arc<AtomicUsize>);

    impl Ledger {
        pub(crate) fn live(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }
    }

    /// One value's part of the ledger, which goes when the value does.
    #[derive(Debug)]
    pub(crate) struct Tally {
        ledger: Arc<AtomicUsize>,
        n: usize,
    }

    impl Tally {
        pub(super) fn new<X>(core: &Core<X>, n: usize) -> Self {
            let ledger = Arc::clone(&core.ledger.0);
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

        pub(super) fn join(mut self, mut other: Tally) -> Tally {
            self.n += std::mem::take(&mut other.n);
            self
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
        pub(crate) fn done(self) {}
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
    pub(crate) struct Tally;

    impl Tally {
        pub(super) fn new<X>(_core: &Core<X>, _n: usize) -> Self {
            Self
        }

        pub(super) fn set(&mut self, _n: usize) {}

        pub(super) fn join(self, _other: Tally) -> Tally {
            self
        }

        pub(super) fn split(&mut self, _n: usize) -> Tally {
            Self
        }

        pub(crate) fn done(self) {}
    }
}
