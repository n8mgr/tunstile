use core::ops::Range;
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

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("invalid packet")]
    InvalidPacket,
}

pub struct Transport {
    our_index: u32,
    peer_index: u32,

    recv_aead: LessSafeKey,
    // TODO: replay protection
    send_aead: LessSafeKey,
    send_counter: u64,
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
            send_counter: 0,
        }
    }

    pub fn our_index(&self) -> u32 {
        self.our_index
    }

    /// Writes an encrypted transport data message to the given buffer.
    pub fn send(&mut self, payload: &[u8], buf: &mut [u8]) {
        if buf.len() != Self::packet_len(payload.len()) {
            panic!("buffer size mismatch");
        }
        buf[0] = MessageType::Data as u8;
        buf[1..4].fill(0);
        buf[DATA_RECEIVER].copy_from_slice(&self.peer_index.to_le_bytes());
        buf[DATA_COUNTER].copy_from_slice(&self.send_counter.to_le_bytes());
        buf[DATA_PAYLOAD_OFFSET..DATA_PAYLOAD_OFFSET + payload.len()].copy_from_slice(payload);
        aead_seal(
            &self.send_aead,
            self.send_counter,
            &[],
            &mut buf[DATA_PAYLOAD_OFFSET..],
        );

        self.send_counter += 1;
    }

    pub const fn packet_len(payload_size: usize) -> usize {
        DATA_PAYLOAD_OFFSET + payload_size + AEAD_TAG_SIZE
    }

    /// Decrypts a received encrypted transport data message
    pub fn receive<'a>(&mut self, packet: &'a mut [u8]) -> Result<&'a [u8], TransportError> {
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
        Ok(plaintext)
    }
}
