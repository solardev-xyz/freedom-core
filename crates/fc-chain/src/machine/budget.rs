//! Deviation `memory-budgets` (design 0005, Bounds): what each request and
//! all of them together may hold.
//!
//! A request is charged for what it holds while it holds it: each answer
//! from the moment main hands it over (its bytes, which the decoded text
//! reuses), the index of an answer while it is read, the texts it retains
//! (a quorum's group answers, Direct's reusable member answer), and the
//! copies it makes. Each charge is released when what it covers is
//! dropped. Replies stay counted in the total after their request ends,
//! until the driver has written them (0004's rule).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

/// The ledger.
#[derive(Debug)]
pub(crate) struct Budget {
    used: BTreeMap<u64, usize>,
    total: usize,
    over: BTreeSet<u64>,
    /// Replies made and not yet taken by the driver.
    output: usize,
    /// Replies the driver has taken and not yet written.
    backlog: usize,
    request_bytes: usize,
    total_bytes: usize,
}

/// Bytes charged to a request, released when dropped.
#[derive(Debug)]
pub struct Charge {
    budget: Option<Rc<RefCell<Budget>>>,
    request: u64,
    bytes: usize,
}

impl Charge {
    /// A charge of nothing (outside any request).
    pub(crate) fn none() -> Self {
        Self {
            budget: None,
            request: 0,
            bytes: 0,
        }
    }

    /// The bytes it holds.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Makes a reservation exact once what it covers is made: the excess
    /// is released, or a shortfall charged. `Err` when the shortfall
    /// crosses a bound: the request is over.
    pub(crate) fn settle(&mut self, actual: usize) -> Result<(), ()> {
        let Some(budget) = &self.budget else {
            return Ok(());
        };
        let mut ledger = budget.borrow_mut();
        if actual <= self.bytes {
            ledger.release(self.request, self.bytes - actual);
            self.bytes = actual;
            return Ok(());
        }
        let extra = actual - self.bytes;
        self.bytes = actual;
        if ledger.add(self.request, extra) {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        if let Some(budget) = self.budget.take() {
            budget.borrow_mut().release(self.request, self.bytes);
        }
    }
}

impl Budget {
    pub(crate) fn new(request_bytes: usize, total_bytes: usize) -> Self {
        Self {
            used: BTreeMap::new(),
            total: 0,
            over: BTreeSet::new(),
            output: 0,
            backlog: 0,
            request_bytes,
            total_bytes,
        }
    }

    fn release(&mut self, request: u64, bytes: usize) {
        if let Some(used) = self.used.get_mut(&request) {
            *used = used.saturating_sub(bytes);
            if *used == 0 {
                self.used.remove(&request);
            }
        }
        self.total = self.total.saturating_sub(bytes);
    }

    /// Everything the total counts: the requests' charges, and the replies
    /// that have left them until they are written.
    pub(crate) fn held(&self) -> usize {
        self.total
            .saturating_add(self.output)
            .saturating_add(self.backlog)
    }

    /// Whether `request` crossed its bound or the total's.
    pub(crate) fn over(&self, request: u64) -> bool {
        self.over.contains(&request)
    }

    /// Whether a new request holding `bytes` from its start may be
    /// admitted: within its own bound, and the total with it.
    pub(crate) fn admits(&self, bytes: usize) -> bool {
        bytes <= self.request_bytes && self.held().saturating_add(bytes) <= self.total_bytes
    }

    /// Adds `bytes` to `request`. False, and the request is over, when that
    /// crosses its bound or the total's.
    fn add(&mut self, request: u64, bytes: usize) -> bool {
        let used = self.used.entry(request).or_default();
        *used = used.saturating_add(bytes);
        let own = *used > self.request_bytes;
        self.total = self.total.saturating_add(bytes);
        let all = self.held() > self.total_bytes;
        if own || all {
            self.over.insert(request);
        }
        !(own || all)
    }

    /// A request ended: it can't be over any more.
    pub(crate) fn forget(&mut self, request: u64) {
        self.over.remove(&request);
    }

    /// What `request` holds now.
    #[cfg(test)]
    pub(crate) fn used(&self, request: u64) -> usize {
        self.used.get(&request).copied().unwrap_or(0)
    }

    pub(crate) fn add_output(&mut self, bytes: usize) {
        self.output = self.output.saturating_add(bytes);
    }

    pub(crate) fn take_output(&mut self) {
        self.output = 0;
    }

    pub(crate) fn set_backlog(&mut self, bytes: usize) {
        self.backlog = bytes;
    }
}

/// Charges `bytes` to `request` (0 charges nothing). `Err` when that
/// crosses the request's bound or the total's: the request is over, and
/// ends with `budget`; the charge is released when dropped either way.
pub(crate) fn charge(
    budget: &Rc<RefCell<Budget>>,
    request: u64,
    bytes: usize,
) -> Result<Charge, Charge> {
    if request == 0 {
        return Ok(Charge::none());
    }
    let within = budget.borrow_mut().add(request, bytes);
    let charge = Charge {
        budget: Some(Rc::clone(budget)),
        request,
        bytes,
    };
    if within { Ok(charge) } else { Err(charge) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charges_are_released_when_dropped() {
        let budget = Rc::new(RefCell::new(Budget::new(100, 150)));
        let a = charge(&budget, 1, 60).unwrap();
        let b = charge(&budget, 1, 40).unwrap();
        assert_eq!(budget.borrow().used(1), 100);
        // One byte more crosses the request's bound.
        let c = charge(&budget, 1, 1).unwrap_err();
        assert!(budget.borrow().over(1));
        drop((a, b, c));
        assert_eq!(budget.borrow().used(1), 0);
        assert_eq!(budget.borrow().held(), 0);
        budget.borrow_mut().forget(1);
        assert!(!budget.borrow().over(1));
    }

    #[test]
    fn a_reservation_settles_to_what_it_covered() {
        let budget = Rc::new(RefCell::new(Budget::new(100, 150)));
        let mut reserved = charge(&budget, 1, 90).unwrap();
        reserved.settle(30).unwrap();
        assert_eq!(budget.borrow().used(1), 30);
        reserved.settle(60).unwrap();
        assert_eq!(budget.borrow().used(1), 60);
        // A shortfall that crosses the bound makes the request over.
        assert!(reserved.settle(101).is_err());
        assert!(budget.borrow().over(1));
        drop(reserved);
        assert_eq!(budget.borrow().held(), 0);
    }

    #[test]
    fn the_total_counts_unwritten_replies() {
        let budget = Rc::new(RefCell::new(Budget::new(100, 150)));
        let _a = charge(&budget, 1, 80).unwrap();
        budget.borrow_mut().add_output(60);
        assert!(budget.borrow().admits(0));
        // Admission judges what the new request brings.
        assert!(budget.borrow().admits(10) && !budget.borrow().admits(11));
        // The request that crosses the total is the one that ends.
        assert!(charge(&budget, 2, 20).is_err());
        assert!(budget.borrow().over(2) && !budget.borrow().over(1));
        budget.borrow_mut().take_output();
        budget.borrow_mut().set_backlog(70);
        assert!(!budget.borrow().admits(1));
        budget.borrow_mut().set_backlog(0);
        assert!(budget.borrow().admits(70));
        assert!(!budget.borrow().admits(101));
        assert!(charge(&budget, 0, usize::MAX).is_ok());
    }
}
