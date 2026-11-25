//! The swarm thread's memory (design 0015, "The swarm thread's memory"):
//! 64 MiB, reserved before use, first in, first out.
//!
//! - **Reserved before use:** a request's base when it is admitted
//!   ([`fc_swarm_provider::machine::REQUEST_CHARGE`]), and each ask's charge
//!   before the ask goes (a whole call's at its form's cap, an upload's
//!   turn, a mining job's). The pool counts charges, never bytes: what a
//!   charge covers is the machine's and the transport's to keep within it.
//! - **First in, first out:** a reservation that doesn't fit, or that
//!   arrives while another waits, waits behind the ones before it, so a
//!   large charge is never passed over by a stream of small ones. The
//!   largest charge, a 5 MiB read at 18.4 MiB, always fits an empty pool.
//! - **Bounded waits** are the engine's: a reservation still waiting at its
//!   request's deadline ends the request `busy` (D13: 60 s for a request
//!   with no total deadline), and is withdrawn here, which lets the ones
//!   behind it through if they fit.
//! - **Releases** are the engine's too, on the design's lifecycle: a call's
//!   charge once the step that consumes its reply ends (or, cancelled, once
//!   main's answer has been read and dropped), a request's base at its end
//!   and once its reply is written.

use std::collections::VecDeque;

/// The swarm thread's memory for requests and bodies (design 0015,
/// "Budgets"), apart from the stores.
pub const POOL: usize = 64 << 20;

/// The pool: what is reserved, and who waits, in order.
#[derive(Debug)]
pub struct Pool<T> {
    capacity: usize,
    used: usize,
    queue: VecDeque<(T, usize)>,
}

impl<T: Copy + PartialEq> Pool<T> {
    pub fn new(capacity: usize) -> Self {
        Pool {
            capacity,
            used: 0,
            queue: VecDeque::new(),
        }
    }

    /// Reserves `amount` for `who`: at once when nothing waits and it fits
    /// (true), or behind the waiting reservations (false), until
    /// [`Pool::release`] or [`Pool::withdraw`] grants it.
    pub fn reserve(&mut self, who: T, amount: usize) -> bool {
        if self.queue.is_empty() && self.fits(amount) {
            self.used += amount;
            return true;
        }
        self.queue.push_back((who, amount));
        false
    }

    fn fits(&self, amount: usize) -> bool {
        self.used
            .checked_add(amount)
            .is_some_and(|total| total <= self.capacity)
    }

    /// Frees `amount`, and grants the waiting reservations that now fit, in
    /// order: the first that doesn't fit holds the rest back.
    pub fn release(&mut self, amount: usize) -> Vec<T> {
        self.used = self.used.saturating_sub(amount);
        self.grant()
    }

    /// `who`'s waiting reservation goes: its request ended, or its ask was
    /// cancelled, before it was granted. The ones behind it may now fit,
    /// and are granted. Nothing for one that doesn't wait.
    pub fn withdraw(&mut self, who: T) -> Vec<T> {
        let before = self.queue.len();
        self.queue.retain(|(w, _)| *w != who);
        if self.queue.len() == before {
            return Vec::new();
        }
        self.grant()
    }

    fn grant(&mut self) -> Vec<T> {
        let mut granted = Vec::new();
        while let Some(&(who, amount)) = self.queue.front() {
            if !self.fits(amount) {
                break;
            }
            self.used += amount;
            self.queue.pop_front();
            granted.push(who);
        }
        granted
    }

    /// What is reserved.
    #[cfg(any(test, feature = "testhooks"))]
    pub fn used(&self) -> usize {
        self.used
    }

    /// Whether `who` waits.
    #[cfg(test)]
    pub fn waits(&self, who: T) -> bool {
        self.queue.iter().any(|(w, _)| *w == who)
    }

    /// How many wait.
    #[cfg(test)]
    pub fn waiting(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_granted_first_in_first_out() {
        let mut pool = Pool::new(10);
        assert!(pool.reserve(1, 6));
        // Doesn't fit: waits.
        assert!(!pool.reserve(2, 6));
        // Fits, but one waits before it: waits too, never passing it.
        assert!(!pool.reserve(3, 1));
        assert_eq!((pool.used(), pool.waiting()), (6, 2));
        // Freed: the first fits, and the second then fits beside it.
        assert_eq!(pool.release(6), vec![2, 3]);
        assert_eq!((pool.used(), pool.waiting()), (7, 0));
        assert_eq!(pool.release(7), Vec::<u32>::new());
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn a_large_reservation_holds_the_small_ones_back() {
        let mut pool = Pool::new(10);
        assert!(pool.reserve(1, 9));
        assert!(!pool.reserve(2, 10));
        assert!(!pool.reserve(3, 1));
        // One byte would let 3 in, but 2 is first.
        assert_eq!(pool.release(1), Vec::<u32>::new());
        assert_eq!(pool.release(8), vec![2]);
        assert!(pool.waits(3));
        assert_eq!(pool.release(10), vec![3]);
    }

    #[test]
    fn a_withdrawn_reservation_lets_the_next_through() {
        let mut pool = Pool::new(10);
        assert!(pool.reserve(1, 5));
        assert!(!pool.reserve(2, 9));
        assert!(!pool.reserve(3, 5));
        assert_eq!(pool.withdraw(2), vec![3]);
        assert_eq!(pool.used(), 10);
        // Nothing waits under that name any more.
        assert_eq!(pool.withdraw(2), Vec::<u32>::new());
        // One past the whole pool waits until withdrawn.
        assert!(!pool.reserve(4, 11));
        assert_eq!(pool.release(10), Vec::<u32>::new());
        assert!(pool.waits(4));
        assert_eq!(pool.withdraw(4), Vec::<u32>::new());
        assert_eq!(pool.waiting(), 0);
    }
}
