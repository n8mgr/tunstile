use core::ops::Range;

use x25519_dalek::PublicKey;
use zeroize::ZeroizeOnDrop;

const AEAD_TAG_SIZE: usize = 16;
const MAC_SIZE: usize = 16;

pub enum Message<'a> {
    HandshakeInit(HandshakeInitMsg),
    HandshakeResponse(HandshakeResponseMsg),
    Transport(TransportDataMsg<'a>),
}

pub struct HandshakeInitMsg {
    pub(crate) sender: u32,
    pub(crate) ephemeral_public_key: PublicKey,
    pub(crate) encrypted_static_public_key: [u8; 32 + AEAD_TAG_SIZE],
    pub(crate) encrypted_timestamp: [u8; 12 + AEAD_TAG_SIZE],
}

impl HandshakeInitMsg {
    // wire layout: [type(1) | reserved(3) | sender(4) | ephemeral(32) | static+tag(48) | timestamp+tag(28) | mac1(16) | mac2(16)]
    pub(crate) const SENDER: Range<usize> = 4..8;
    pub(crate) const EPHEMERAL: Range<usize> = Self::SENDER.end..Self::SENDER.end + 32;
    pub(crate) const STATIC: Range<usize> =
        Self::EPHEMERAL.end..Self::EPHEMERAL.end + 32 + AEAD_TAG_SIZE;
    pub(crate) const TIMESTAMP: Range<usize> =
        Self::STATIC.end..Self::STATIC.end + 12 + AEAD_TAG_SIZE;
    pub(crate) const MAC1: Range<usize> = Self::TIMESTAMP.end..Self::TIMESTAMP.end + MAC_SIZE;
    pub(crate) const MAC2: Range<usize> = Self::MAC1.end..Self::MAC1.end + MAC_SIZE;

    pub const MESSAGE_TYPE: u8 = 0x01;
    pub const MESSAGE_LENGTH: usize = Self::MAC2.end;

    pub fn decode(buf: &[u8]) -> Self {
        if buf.len() != Self::MESSAGE_LENGTH {
            panic!("Invalid buffer length")
        } else if buf[0] != Self::MESSAGE_TYPE {
            panic!("Invalid message type")
        }
        let sender = u32::from_le_bytes(buf[Self::SENDER].try_into().unwrap());
        let ephemeral_public_key =
            PublicKey::from(<[u8; 32]>::try_from(&buf[Self::EPHEMERAL]).unwrap());
        let encrypted_static_public_key = buf[Self::STATIC].try_into().unwrap();
        let encrypted_timestamp = buf[Self::TIMESTAMP].try_into().unwrap();
        Self {
            sender,
            ephemeral_public_key,
            encrypted_static_public_key,
            encrypted_timestamp,
        }
    }

    pub fn sender(&self) -> u32 {
        self.sender
    }

    pub fn ephemeral_public_key(&self) -> &PublicKey {
        &self.ephemeral_public_key
    }
}

#[derive(ZeroizeOnDrop)]
pub struct HandshakeResponseMsg {
    pub(crate) sender: u32,
    pub(crate) receiver: u32,
    pub(crate) ephemeral_public_key: PublicKey,
    pub(crate) encrypted_empty_tag: [u8; 16],
}

impl HandshakeResponseMsg {
    // wire layout: [type(1) | reserved(3) | sender(4) | receiver(4) | ephemeral(32) | empty_tag(16) | mac1(16) | mac2(16)]
    pub(crate) const SENDER: Range<usize> = 4..8;
    pub(crate) const RECEIVER: Range<usize> = Self::SENDER.end..Self::SENDER.end + 4;
    pub(crate) const EPHEMERAL: Range<usize> = Self::RECEIVER.end..Self::RECEIVER.end + 32;
    pub(crate) const EMPTY_TAG: Range<usize> =
        Self::EPHEMERAL.end..Self::EPHEMERAL.end + AEAD_TAG_SIZE;
    pub(crate) const MAC1: Range<usize> = Self::EMPTY_TAG.end..Self::EMPTY_TAG.end + MAC_SIZE;
    pub(crate) const MAC2: Range<usize> = Self::MAC1.end..Self::MAC1.end + MAC_SIZE;

    pub const MESSAGE_TYPE: u8 = 0x02;
    pub const MESSAGE_LENGTH: usize = Self::MAC2.end;

    pub fn decode(buf: &[u8]) -> Self {
        if buf.len() != Self::MESSAGE_LENGTH {
            panic!("Invalid message length")
        } else if buf[0] != Self::MESSAGE_TYPE {
            panic!("Invalid message type")
        }
        let sender = u32::from_le_bytes(buf[Self::SENDER].try_into().unwrap());
        let receiver = u32::from_le_bytes(buf[Self::RECEIVER].try_into().unwrap());
        let ephemeral_public_key =
            PublicKey::from(<[u8; 32]>::try_from(&buf[Self::EPHEMERAL]).unwrap());
        let encrypted_empty_tag = buf[Self::EMPTY_TAG].try_into().unwrap();
        Self {
            sender,
            receiver,
            ephemeral_public_key,
            encrypted_empty_tag,
        }
    }

    pub fn sender(&self) -> u32 {
        self.sender
    }

    pub fn receiver(&self) -> u32 {
        self.receiver
    }

    pub fn ephemeral_public_key(&self) -> &PublicKey {
        &self.ephemeral_public_key
    }
}

pub struct TransportDataMsg<'a> {
    pub(crate) receiver: u32,
    pub(crate) counter: u64,
    pub(crate) encrypted_payload: &'a mut [u8],
}

impl<'a> TransportDataMsg<'a> {
    pub const MESSAGE_TYPE: u8 = 0x03;

    // wire layout: [type(1) | reserved(3) | receiver(4) | counter(8) | payload+tag(...)]
    pub(crate) const RECEIVER: Range<usize> = 4..8;
    pub(crate) const COUNTER: Range<usize> = Self::RECEIVER.end..Self::RECEIVER.end + 8;
    pub(crate) const PAYLOAD_OFFSET: usize = Self::COUNTER.end;

    pub fn encoded_len(payload_len: usize) -> usize {
        Self::PAYLOAD_OFFSET + payload_len + AEAD_TAG_SIZE
    }

    pub fn decode(buf: &'a mut [u8]) -> Self {
        let receiver = u32::from_le_bytes(buf[Self::RECEIVER].try_into().unwrap());
        let counter = u64::from_le_bytes(buf[Self::COUNTER].try_into().unwrap());
        let encrypted_payload = &mut buf[Self::PAYLOAD_OFFSET..];
        Self {
            receiver,
            counter,
            encrypted_payload,
        }
    }

    pub fn receiver(&self) -> u32 {
        self.receiver
    }
}
