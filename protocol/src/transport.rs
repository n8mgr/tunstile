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

    /// Writes an encrypted transport data message to the given buffer.
    pub fn send(&mut self, payload: &[u8], buf: &mut [u8]) {
        use TransportDataMsg as M;
        if buf.len() != M::encoded_len(payload.len()) {
            panic!("buffer size mismatch");
        }
        buf[0] = M::MESSAGE_TYPE;
        buf[1..4].fill(0);
        buf[M::RECEIVER].copy_from_slice(&self.peer_index.to_le_bytes());
        buf[M::COUNTER].copy_from_slice(&self.send_counter.to_le_bytes());
        buf[M::PAYLOAD_OFFSET..M::PAYLOAD_OFFSET + payload.len()].copy_from_slice(payload);
        aead_seal(
            &mut self.send_aead,
            self.send_counter,
            &[],
            &mut buf[M::PAYLOAD_OFFSET..],
        );

        self.send_counter += 1;
    }

    /// Decrypts a received encrypted transport data message
    pub fn receive<'a>(&mut self, packet: TransportDataMsg<'a>) -> Result<&'a [u8], bool> {
        let (cipher_text, tag) = packet
            .encrypted_payload
            .split_at_mut(packet.encrypted_payload.len() - 16);
        aead_open(&mut self.recv_aead, packet.counter, &[], cipher_text, tag).map_err(|_| false)?;
        Ok(cipher_text)
    }
}
