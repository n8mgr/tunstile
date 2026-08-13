use core::time::Duration;

use crate::{
    time::Instant,
    transport::{ReplayFilter, Transport, TransportError},
};

/// Handshake retransmission interval.
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// Exclusive upper bound for random milliseconds added to rekey timers.
pub const REKEY_TIMEOUT_JITTER_MAX: Duration = Duration::from_millis(334);
/// Give up retransmitting a handshake after this long.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// An initiator rekeys when sending on a session older than this.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// A session refuses to encrypt or decrypt once older than this.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// Received data must be answered within this window, with a keepalive if
/// nothing else.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// An initiator rekeys when receiving on a session this close to expiry.
pub const REKEY_AFTER_TIME_RECEIVING: Duration = Duration::from_secs(
    REJECT_AFTER_TIME.as_secs() - KEEPALIVE_TIMEOUT.as_secs() - REKEY_TIMEOUT.as_secs(),
);
pub(super) enum SessionReceiveError {
    Invalid,
    Replay,
}

pub(super) struct Session {
    transport: Transport,
    established: Instant,
    replay: ReplayFilter,
}

impl Session {
    pub(super) fn new(transport: Transport, now: Instant) -> Self {
        Self {
            transport,
            established: now,
            replay: ReplayFilter::new(),
        }
    }

    pub(super) fn our_index(&self) -> u32 {
        self.transport.our_index()
    }

    pub(super) fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.established) >= REJECT_AFTER_TIME
    }

    pub(super) fn rekey_due_to_messages(&self) -> bool {
        self.transport.rekey_due()
    }

    pub(super) fn send(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, TransportError> {
        self.transport.send(payload, out)
    }

    pub(super) fn receive(&mut self, packet: &mut [u8]) -> Result<usize, SessionReceiveError> {
        let (counter, payload_len) = self
            .transport
            .receive(packet)
            .map_err(|_| SessionReceiveError::Invalid)?;
        if !self.replay.validate(counter) {
            return Err(SessionReceiveError::Replay);
        }
        Ok(payload_len)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{Hash256, init_aead};

    use super::*;

    fn session(established: Instant) -> Session {
        let key = Hash256::default();
        Session::new(
            Transport::new(1, 2, init_aead(&key), init_aead(&key)),
            established,
        )
    }

    #[test]
    fn expires_at_reject_after_time() {
        let established = Instant::default();
        let session = session(established);

        assert!(!session.expired(established + (REJECT_AFTER_TIME - Duration::from_millis(1))));
        assert!(session.expired(established + REJECT_AFTER_TIME));
    }
}
