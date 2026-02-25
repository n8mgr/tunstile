use chacha20poly1305::ChaCha20Poly1305;
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{aead_open, aead_seal},
    messages::TransportDataMsg,
};

#[derive(ZeroizeOnDrop)]
pub struct Transport {
    our_index: u32,
    peer_index: u32,

    recv_aead: ChaCha20Poly1305,
    // TODO: replay protection
    send_aead: ChaCha20Poly1305,
    send_counter: u64,
}

impl Transport {
    pub(crate) fn new(
        our_index: u32,
        peer_index: u32,
        recv_aead: ChaCha20Poly1305,
        send_aead: ChaCha20Poly1305,
    ) -> Self {
        Self {
            our_index,
            peer_index,

            recv_aead,

            send_aead,
            send_counter: 0,
        }
    }

    /// Constructs a new `TransportDataMsg` with the given packet.
    /// Packet must have space for the 16 byte authentication tag.
    pub fn seal<'a>(&mut self, packet: &'a mut [u8]) -> TransportDataMsg<'a> {
        aead_seal(&mut self.send_aead, self.send_counter, &[], packet);

        let t = TransportDataMsg {
            receiver: self.peer_index,
            counter: self.send_counter,
            packet,
        };

        self.send_counter += 1;
        t
    }

    pub fn open<'a>(&mut self, packet: TransportDataMsg<'a>) -> Result<&'a [u8], bool> {
        let (cipher_text, tag) = packet.packet.split_at_mut(packet.packet.len() - 16);
        aead_open(&mut self.recv_aead, packet.counter, &[], cipher_text, tag).map_err(|_| false)?;
        Ok(cipher_text)
    }
}
