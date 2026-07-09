use core::{
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};
use ring::aead::LessSafeKey;
use thiserror::Error;

use crate::{
    AEAD_TAG_SIZE, MessageType,
    crypto::{aead_open, aead_seal},
};

// data msg wire layout: [type(1) | reserved(3) | receiver(4) | counter(8) | payload+tag(...)]
pub(crate) const DATA_RECEIVER: Range<usize> = 4..8;
pub(crate) const DATA_COUNTER: Range<usize> = DATA_RECEIVER.end..DATA_RECEIVER.end + 8;
const DATA_PAYLOAD_OFFSET: usize = DATA_COUNTER.end;

const COUNTER_BLOCK_BITS: u64 = 64;
const COUNTER_BLOCKS: usize = 128;
const COUNTER_WINDOW: u64 = (COUNTER_BLOCKS as u64 - 1) * COUNTER_BLOCK_BITS;

/// Reject-After-Messages from the WireGuard spec: 2^64 − 2^13 − 1.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("invalid packet")]
    InvalidPacket,
}

/// Sliding-window duplicate detection for received counters (RFC 6479).
///
/// Callers must only validate counters from packets that already passed
/// authentication, or an attacker can poison the window.
pub struct ReplayFilter {
    last: u64,
    ring: [u64; COUNTER_BLOCKS],
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayFilter {
    pub const fn new() -> Self {
        Self {
            last: 0,
            ring: [0; COUNTER_BLOCKS],
        }
    }

    /// Marks a counter used. Returns false if it was already used, is older
    /// than the window, or exceeds Reject-After-Messages.
    pub fn validate(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let index_block = counter / COUNTER_BLOCK_BITS;
        if counter > self.last {
            let current_block = self.last / COUNTER_BLOCK_BITS;
            let diff = (index_block - current_block).min(COUNTER_BLOCKS as u64);
            for i in current_block + 1..=current_block + diff {
                self.ring[(i % COUNTER_BLOCKS as u64) as usize] = 0;
            }
            self.last = counter;
        } else if self.last - counter > COUNTER_WINDOW {
            return false;
        }
        let bit = 1u64 << (counter % COUNTER_BLOCK_BITS);
        let block = &mut self.ring[(index_block % COUNTER_BLOCKS as u64) as usize];
        if *block & bit != 0 {
            return false;
        }
        *block |= bit;
        true
    }
}

pub struct Transport {
    our_index: u32,
    peer_index: u32,

    recv_aead: LessSafeKey,
    send_aead: LessSafeKey,
    send_counter: AtomicU64,
}

impl Transport {
    pub(crate) fn new(
        our_index: u32,
        peer_index: u32,
        recv_aead: LessSafeKey,
        send_aead: LessSafeKey,
    ) -> Self {
        Self {
            our_index,
            peer_index,

            recv_aead,

            send_aead,
            send_counter: AtomicU64::new(0),
        }
    }

    pub fn our_index(&self) -> u32 {
        self.our_index
    }

    /// Writes an encrypted transport data message to the given buffer.
    pub fn send(&self, payload: &[u8], buf: &mut [u8]) {
        if buf.len() != Self::packet_len(payload.len()) {
            panic!("buffer size mismatch");
        }
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        buf[0] = MessageType::Data as u8;
        buf[1..4].fill(0);
        buf[DATA_RECEIVER].copy_from_slice(&self.peer_index.to_le_bytes());
        buf[DATA_COUNTER].copy_from_slice(&counter.to_le_bytes());
        buf[DATA_PAYLOAD_OFFSET..DATA_PAYLOAD_OFFSET + payload.len()].copy_from_slice(payload);
        aead_seal(
            &self.send_aead,
            counter,
            &[],
            &mut buf[DATA_PAYLOAD_OFFSET..],
        );
    }

    pub const fn packet_len(payload_size: usize) -> usize {
        DATA_PAYLOAD_OFFSET + payload_size + AEAD_TAG_SIZE
    }

    /// Decrypts a received encrypted transport data message, returning its
    /// counter and payload. The counter must be checked against a
    /// [`ReplayFilter`] before the payload is trusted.
    pub fn receive<'a>(&self, packet: &'a mut [u8]) -> Result<(u64, &'a [u8]), TransportError> {
        if packet.len() < Self::packet_len(0)
            || MessageType::try_from(packet[0]) != Ok(MessageType::Data)
        {
            return Err(TransportError::InvalidPacket);
        }
        let receiver = u32::from_le_bytes(
            packet[DATA_RECEIVER]
                .try_into()
                .map_err(|_| TransportError::InvalidPacket)?,
        );
        if receiver != self.our_index {
            return Err(TransportError::InvalidPacket);
        }
        let counter = u64::from_le_bytes(
            packet[DATA_COUNTER]
                .try_into()
                .map_err(|_| TransportError::InvalidPacket)?,
        );
        let plaintext = aead_open(
            &self.recv_aead,
            counter,
            &[],
            &mut packet[DATA_PAYLOAD_OFFSET..],
        )
        .map_err(|_| TransportError::InvalidPacket)?;
        Ok((counter, &*plaintext))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn replay_filter() {
        let mut filter = ReplayFilter::new();

        // in-order counters validate once
        for counter in 0..10 {
            assert!(filter.validate(counter), "fresh counter {counter}");
            assert!(!filter.validate(counter), "replayed counter {counter}");
        }

        // out of order within the window
        let mut filter = ReplayFilter::new();
        assert!(filter.validate(100));
        assert!(filter.validate(50));
        assert!(filter.validate(99));
        assert!(!filter.validate(50));

        // older than the window
        let mut filter = ReplayFilter::new();
        assert!(filter.validate(COUNTER_WINDOW + 1));
        assert!(!filter.validate(0));
        assert!(filter.validate(1));

        // a large jump clears the intermediate window state
        let mut filter = ReplayFilter::new();
        assert!(filter.validate(0));
        assert!(filter.validate(10 * COUNTER_WINDOW));
        assert!(!filter.validate(0));
        assert!(filter.validate(10 * COUNTER_WINDOW - COUNTER_WINDOW));

        // counter limit
        let mut filter = ReplayFilter::new();
        assert!(!filter.validate(REJECT_AFTER_MESSAGES));
        assert!(!filter.validate(u64::MAX));
        assert!(filter.validate(REJECT_AFTER_MESSAGES - 1));
    }
}
