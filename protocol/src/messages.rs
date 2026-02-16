use x25519_dalek::PublicKey;

const AEAD_TAG_SIZE: usize = 16;

pub trait HandshakeMessageWriter {
    fn write_message(&mut self, msg: HandshakeMessage);
}

pub enum HandshakeMessage {
    Init(HandshakeInitMsg),
    Response(HandshakeResponseMsg),
}

pub struct HandshakeInitMsg {
    pub sender: u32,
    pub ephemeral_public_key: PublicKey,
    pub encrypted_static_public_key: [u8; 32 + AEAD_TAG_SIZE],
    pub encrypted_timestamp: [u8; 12 + AEAD_TAG_SIZE],
    pub mac_1: [u8; 16],
    pub mac_2: [u8; 16],
}

impl HandshakeInitMsg {
    pub const MESSAGE_TYPE: u8 = 0x01;
    pub const MESSAGE_LENGTH: usize = 4 + 4 + 32 + 48 + 28 + 16 + 16;

    pub fn encode(&self, buf: &mut [u8; Self::MESSAGE_LENGTH]) {
        buf[0] = Self::MESSAGE_TYPE;
        buf[1..4].fill(0); // reserved
        buf[4..8].copy_from_slice(&self.sender.to_le_bytes());
        buf[8..40].copy_from_slice(self.ephemeral_public_key.as_bytes());
        buf[40..88].copy_from_slice(&self.encrypted_static_public_key);
        buf[88..116].copy_from_slice(&self.encrypted_timestamp);
        buf[116..132].copy_from_slice(&self.mac_1);
        buf[132..148].copy_from_slice(&self.mac_2);
    }

    pub fn decode(buf: &[u8; Self::MESSAGE_LENGTH]) -> Self {
        let sender = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let ephemeral_public_key = PublicKey::from(<[u8; 32]>::try_from(&buf[8..40]).unwrap());
        let encrypted_static_public_key = buf[40..88].try_into().unwrap();
        let encrypted_timestamp = buf[88..116].try_into().unwrap();
        let mac_1 = buf[116..132].try_into().unwrap();
        let mac_2 = buf[132..148].try_into().unwrap();
        Self {
            sender,
            ephemeral_public_key,
            encrypted_static_public_key,
            encrypted_timestamp,
            mac_1,
            mac_2,
        }
    }
}

pub struct HandshakeResponseMsg {
    pub sender: u32,
    pub receiver: u32,
    pub ephemeral_public_key: PublicKey,
    pub encrypted_empty_tag: [u8; AEAD_TAG_SIZE],
    pub mac_1: [u8; 16],
    pub mac_2: [u8; 16],
}

impl HandshakeResponseMsg {
    pub const MESSAGE_TYPE: u8 = 0x02;
    pub const MESSAGE_LENGTH: usize = 4 + 4 + 4 + 32 + 16 + 16 + 16;

    pub fn encode(&self, buf: &mut [u8; Self::MESSAGE_LENGTH]) {
        buf[0] = Self::MESSAGE_TYPE;
        buf[1..4].fill(0); // reserved
        buf[4..8].copy_from_slice(&self.sender.to_le_bytes());
        buf[8..12].copy_from_slice(&self.receiver.to_le_bytes());
        buf[12..44].copy_from_slice(self.ephemeral_public_key.as_bytes());
        buf[44..60].copy_from_slice(&self.encrypted_empty_tag);
        buf[60..76].copy_from_slice(&self.mac_1);
        buf[76..92].copy_from_slice(&self.mac_2);
    }

    pub fn decode(buf: &[u8; Self::MESSAGE_LENGTH]) -> Self {
        let sender = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let receiver = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let ephemeral_public_key = PublicKey::from(<[u8; 32]>::try_from(&buf[12..44]).unwrap());
        let encrypted_empty_tag = buf[44..60].try_into().unwrap();
        let mac_1 = buf[60..76].try_into().unwrap();
        let mac_2 = buf[76..92].try_into().unwrap();
        Self {
            sender,
            receiver,
            ephemeral_public_key,
            encrypted_empty_tag,
            mac_1,
            mac_2,
        }
    }
}

pub struct TransportDataMsg<'a> {
    pub receiver: u32,
    pub counter: u64,
    pub packet: &'a [u8],
}
