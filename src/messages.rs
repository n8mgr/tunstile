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

pub struct HandshakeResponseMsg {
    pub sender: u32,
    pub receiver: u32,
    pub ephemeral_public_key: PublicKey,
    pub encrypted_empty_tag: [u8; AEAD_TAG_SIZE],
    pub mac_1: [u8; 16],
    pub mac_2: [u8; 16],
}

pub struct TransportDataMsg<'a> {
    pub receiver: u32,
    pub counter: u64,
    pub packet: &'a [u8],
}
