//! Sans-I/O WireGuard handshake, transport, cookie, and per-peer state
//! machinery. The caller supplies packet buffers, time, randomness, and
//! scheduling.
//!
//! # Example
//!
//! ```
//! use tunstile_protocol::{PrivateKey, PublicKey, peer::Peer};
//!
//! fn new_peer(private_key: PrivateKey, public_key: PublicKey) -> Peer {
//!     Peer::new(private_key, public_key)
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

const AEAD_TAG_SIZE: usize = 16;
const MAC_SIZE: usize = 16;

/// Error parsing a message type byte.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MessageTypeParseError {
    #[error("invalid message type")]
    InvalidMessageType,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum MessageType {
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    Cookie = 0x03,
    Data = 0x04,
}

impl TryFrom<u8> for MessageType {
    type Error = MessageTypeParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == MessageType::HandshakeInit as u8 => Ok(MessageType::HandshakeInit),
            x if x == MessageType::HandshakeResp as u8 => Ok(MessageType::HandshakeResp),
            x if x == MessageType::Cookie as u8 => Ok(MessageType::Cookie),
            x if x == MessageType::Data as u8 => Ok(MessageType::Data),
            _ => Err(MessageTypeParseError::InvalidMessageType),
        }
    }
}

/// Error parsing a [`MessageHeader`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MessageHeaderParseError {
    #[error("invalid message header length")]
    InvalidLength,

    #[error("invalid message header")]
    InvalidHeader,

    #[error("invalid message type: {0}")]
    InvalidMessageType(#[from] MessageTypeParseError),

    #[error("invalid peer index")]
    InvalidPeerIndex,
}

/// The type and receiver index of a validated WireGuard message, parsed from
/// its leading bytes.
pub enum MessageHeader {
    HandshakeInit,
    HandshakeResponse { receiver: u32 },
    CookieReply { receiver: u32 },
    Data { receiver: u32 },
}

impl TryFrom<&[u8]> for MessageHeader {
    type Error = MessageHeaderParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 4 {
            return Err(MessageHeaderParseError::InvalidLength);
        }
        let msg_type = MessageType::try_from(value[0])?;
        if value[1..4] != [0; 3] {
            return Err(MessageHeaderParseError::InvalidHeader);
        }
        let valid_length = match msg_type {
            MessageType::HandshakeInit => value.len() == handshake::INIT_MSG_LENGTH,
            MessageType::HandshakeResp => value.len() == handshake::RESP_MSG_LENGTH,
            MessageType::Cookie => value.len() == cookies::COOKIE_REPLY_LENGTH,
            MessageType::Data => value.len() >= transport::Transport::packet_len(0),
        };
        if !valid_length {
            return Err(MessageHeaderParseError::InvalidLength);
        }
        let index_range = match msg_type {
            MessageType::HandshakeInit | MessageType::Cookie | MessageType::Data => 4..8,
            MessageType::HandshakeResp => 8..12,
        };
        let index = <u32>::from_le_bytes(value[index_range].try_into().unwrap());
        Ok(match msg_type {
            MessageType::HandshakeInit => MessageHeader::HandshakeInit,
            MessageType::Cookie => MessageHeader::CookieReply { receiver: index },
            MessageType::HandshakeResp => MessageHeader::HandshakeResponse { receiver: index },
            MessageType::Data => MessageHeader::Data { receiver: index },
        })
    }
}

mod crypto;
mod keys;
pub mod transport;

pub mod cookies;
pub mod handshake;
pub mod peer;
pub mod time;

pub use keys::{KeyParseError, PrivateKey, PublicKey};
pub use tai64::*;
use thiserror::Error;
pub use x25519_dalek::ReusableSecret;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_header_rejects_reserved_bytes() {
        let mut packet = [0u8; handshake::INIT_MSG_LENGTH];
        packet[0] = MessageType::HandshakeInit as u8;
        packet[1] = 1;
        assert!(matches!(
            MessageHeader::try_from(packet.as_slice()),
            Err(MessageHeaderParseError::InvalidHeader)
        ));
    }

    #[test]
    fn message_header_rejects_wrong_fixed_length() {
        let mut packet = [0u8; handshake::INIT_MSG_LENGTH + 1];
        packet[0] = MessageType::HandshakeInit as u8;
        assert!(matches!(
            MessageHeader::try_from(packet.as_slice()),
            Err(MessageHeaderParseError::InvalidLength)
        ));
    }
}
