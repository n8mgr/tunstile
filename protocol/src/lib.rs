#![no_std]

const AEAD_TAG_SIZE: usize = 16;
const MAC_SIZE: usize = 16;

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

pub enum MessageHeader {
    HandshakeInit,
    HandshakeResponse { receiver: u32 },
    CookieReply { receiver: u32 },
    Data { receiver: u32 },
}

impl TryFrom<&[u8]> for MessageHeader {
    type Error = MessageHeaderParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(MessageHeaderParseError::InvalidLength);
        }
        let msg_type = MessageType::try_from(value[0])?;
        let index_range = match msg_type {
            MessageType::HandshakeInit | MessageType::Cookie | MessageType::Data => 4..8,
            MessageType::HandshakeResp => 8..12,
        };
        if value.len() < index_range.end {
            return Err(MessageHeaderParseError::InvalidLength);
        }
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
pub mod transport;

pub mod cookies;
pub mod handshake;

pub use tai64::*;
use thiserror::Error;
pub use x25519_dalek::{PublicKey, StaticSecret};
