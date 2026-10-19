//! The vault's clock: milliseconds since the core started, counting the time
//! the machine spends asleep (#80).
//!
//! `Instant` doesn't count it on Linux (`CLOCK_MONOTONIC`) or macOS
//! (`CLOCK_UPTIME_RAW`). With `Instant` alone, a vault left unlocked with 14
//! minutes to go still had 14 minutes after three days asleep.
//!
//! So each reading advances the clock by the larger of what two clocks say
//! has passed since the previous reading:
//!
//! - **the monotonic clock** (`Instant`), which never runs backwards;
//! - **the wall clock** (`SystemTime`), which keeps counting while the
//!   machine sleeps.
//!
//! The wall clock can only make this clock run ahead, never hold it back:
//! - **Set back:** the monotonic reading carries the clock, and the wall clock
//!   is measured from its new value on.
//! - **Set forward:** the clock jumps with it. That means an early auto-lock,
//!   or a throttle delay that ends early. Setting the system clock needs
//!   administrator rights, which the design doesn't defend against.
//!
//! The clock never runs backwards, and never stops while the monotonic clock
//! runs.

use std::cell::Cell;
use std::time::{Duration, Instant, SystemTime};

pub struct Clock {
    /// The previous reading of each clock, and the time counted so far.
    last: Cell<Reading>,
}

#[derive(Clone, Copy)]
struct Reading {
    mono: Instant,
    wall: SystemTime,
    elapsed: Duration,
}

impl Clock {
    pub fn new() -> Self {
        Self::starting_at(Instant::now(), SystemTime::now())
    }

    fn starting_at(mono: Instant, wall: SystemTime) -> Self {
        Clock {
            last: Cell::new(Reading {
                mono,
                wall,
                elapsed: Duration::ZERO,
            }),
        }
    }

    /// Milliseconds since the clock started, sleep included.
    pub fn now_ms(&self) -> u64 {
        self.at(Instant::now(), SystemTime::now())
    }

    fn at(&self, mono: Instant, wall: SystemTime) -> u64 {
        let last = self.last.get();
        let by_mono = mono.saturating_duration_since(last.mono);
        // Set back: nothing passed by this clock.
        let by_wall = wall.duration_since(last.wall).unwrap_or_default();
        let elapsed = last.elapsed.saturating_add(by_mono.max(by_wall));
        self.last.set(Reading {
            mono: mono.max(last.mono),
            wall,
            elapsed,
        });
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
    }

    /// Tests: the machine slept for `asleep` since the last reading. The
    /// monotonic clock stood still while the wall clock ran on.
    #[cfg(test)]
    pub fn sleep(&self, asleep: Duration) {
        let mut last = self.last.get();
        last.wall = last.wall.checked_sub(asleep).unwrap_or(last.wall);
        self.last.set(last);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);
    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    fn ms(d: Duration) -> u64 {
        u64::try_from(d.as_millis()).unwrap()
    }

    #[test]
    fn time_asleep_counts() {
        let (m0, w0) = (Instant::now(), SystemTime::now());
        let clock = Clock::starting_at(m0, w0);
        assert_eq!(clock.at(m0 + MINUTE, w0 + MINUTE), ms(MINUTE));
        // Three days asleep: the monotonic clock moved by a second.
        let woke = clock.at(m0 + MINUTE + Duration::from_secs(1), w0 + MINUTE + 3 * DAY);
        assert_eq!(woke, ms(MINUTE + 3 * DAY));
        // Then both run together again.
        let later = clock.at(
            m0 + 2 * MINUTE + Duration::from_secs(1),
            w0 + 2 * MINUTE + 3 * DAY,
        );
        assert_eq!(later, ms(2 * MINUTE + 3 * DAY));
    }

    #[test]
    fn a_wall_clock_set_back_holds_nothing_back() {
        let (m0, w0) = (Instant::now(), SystemTime::now());
        let clock = Clock::starting_at(m0, w0);
        assert_eq!(clock.at(m0 + MINUTE, w0 + MINUTE), ms(MINUTE));
        // Set back a day: the monotonic minute counts.
        assert_eq!(
            clock.at(m0 + 2 * MINUTE, w0 + 2 * MINUTE - DAY),
            ms(2 * MINUTE)
        );
        // And from there, the wall clock is measured from its new value: a
        // day asleep after it (with a minute more on the wall clock) counts
        // in full.
        assert_eq!(
            clock.at(m0 + 2 * MINUTE + Duration::from_secs(1), w0 + 3 * MINUTE),
            ms(3 * MINUTE + DAY)
        );
    }

    #[test]
    fn the_monotonic_clock_carries_it_and_it_never_runs_backwards() {
        let (m0, w0) = (Instant::now(), SystemTime::now());
        let clock = Clock::starting_at(m0, w0);
        // A wall clock that stands still (or is slow) doesn't stop it.
        assert_eq!(clock.at(m0 + MINUTE, w0), ms(MINUTE));
        assert_eq!(clock.at(m0 + 2 * MINUTE, w0), ms(2 * MINUTE));
        // An earlier monotonic reading than the last one changes nothing.
        assert_eq!(clock.at(m0, w0), ms(2 * MINUTE));
        let real = Clock::new();
        let first = real.now_ms();
        assert!(real.now_ms() >= first);
    }
}
