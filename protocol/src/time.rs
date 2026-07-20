//! Clock-free time types for the sans-IO state machines.

use core::ops::{Add, AddAssign, Sub};

pub use core::time::Duration;

/// A monotonic timestamp with millisecond resolution, measured from an
/// arbitrary epoch chosen by the caller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// An instant `millis` after the epoch.
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the epoch.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Time elapsed since `earlier`, or zero if `earlier` is later.
    pub const fn duration_since(self, earlier: Instant) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Instant {
        Instant(self.0.saturating_add(rhs.as_millis() as u64))
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, rhs: Duration) -> Instant {
        Instant(self.0.saturating_sub(rhs.as_millis() as u64))
    }
}
