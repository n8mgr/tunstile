//! Clock-free time types for the sans-IO state machines.

use core::ops::Add;

pub use core::time::Duration;

/// A point on the driver's monotonic clock: the time elapsed since an
/// arbitrary epoch of the driver's choosing. The newtype keeps points and
/// spans apart — comparing or exchanging an `Instant` with a bare
/// [`Duration`] is a type error unless converted explicitly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

impl Instant {
    /// Time elapsed since `earlier`, or zero if `earlier` is later.
    pub const fn duration_since(self, earlier: Instant) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

impl From<Duration> for Instant {
    fn from(since_epoch: Duration) -> Self {
        Self(since_epoch)
    }
}

impl From<Instant> for Duration {
    fn from(instant: Instant) -> Self {
        instant.0
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Instant {
        Instant(self.0.saturating_add(rhs))
    }
}
