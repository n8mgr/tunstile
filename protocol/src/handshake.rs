use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use tai64::Tai64N;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::{
    cookies::Generator,
    crypto::{Hash256, aead_open, aead_seal, hash, kdf},
    messages::{HandshakeInitMsg, HandshakeResponseMsg},
    transport::Transport,
};

// C := HASH(Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s)
const INITIAL_CONSTR_HASH: &[u8] = &[
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];
// H := HASH(C || WireGuard v1 zx2c4 Jason@zx2c4.com)
const INITIAL_IDENTIFIER_HASH: &[u8] = &[
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

pub struct Handshake<S> {
    our_private: StaticSecret,
    our_public: PublicKey,
    peer_public: PublicKey,

    state: S,
}

// pre-init state
pub struct Created;

// initiator state
#[derive(ZeroizeOnDrop)]
pub struct InitSent {
    index_initiator: u32,
    ephemeral_secret_initiator: StaticSecret,

    constr: Hash256,
    h: Hash256,
}

// responder state
#[derive(ZeroizeOnDrop)]
pub struct InitReceived {
    ephemeral_public_initiator: PublicKey,
    index_initiator: u32,

    constr: Hash256,
    h: Hash256,
}

#[derive(ZeroizeOnDrop)]
pub struct ReceiverEstablished {
    our_index: u32,
    peer_index: u32,
    constr: Hash256,
}

#[derive(ZeroizeOnDrop)]
pub struct InitiatorEstablished {
    our_index: u32,
    peer_index: u32,
    constr: Hash256,
}

impl Handshake<Created> {
    pub fn new(our_private: StaticSecret, peer_public: PublicKey) -> Self {
        let our_public = PublicKey::from(&our_private);
        Handshake {
            our_private,
            our_public,
            peer_public,
            state: Created {},
        }
    }

    /// Parses a received handshake initiator message
    pub fn receive(self, received: HandshakeInitMsg) -> Handshake<InitReceived> {
        let constr = INITIAL_CONSTR_HASH;
        let h = hash(&[INITIAL_IDENTIFIER_HASH, self.our_public.as_ref()]);
        let ephemeral_public_initiator = received.ephemeral_public_key;
        let [constr] = kdf::<1>(constr, ephemeral_public_initiator.as_ref());
        let h = hash(&[h.as_ref(), ephemeral_public_initiator.as_ref()]);
        let shared_secret = self.our_private.diffie_hellman(&ephemeral_public_initiator);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());
        let mut aead = ChaCha20Poly1305::new(key.as_ref().into());

        // copied because the encrypted bytes are used in the hash after open
        let mut peer_static_public_key = [0u8; 32];
        peer_static_public_key.copy_from_slice(&received.encrypted_static_public_key[..32]);
        let tag = &received.encrypted_static_public_key[32..];
        aead_open(&mut aead, 0, h.as_ref(), &mut peer_static_public_key, tag).unwrap(); // TODO: handle error
        if self.peer_public.to_bytes() != peer_static_public_key {
            panic!("Invalid peer public key")
        }
        let h = hash(&[h.as_ref(), &received.encrypted_static_public_key]);

        let shared_secret = self.our_private.diffie_hellman(&self.peer_public);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());
        let mut aead = ChaCha20Poly1305::new(key.as_ref().into());

        // copied because the encrypted bytes are used in the hash after open
        let mut timestamp_buf = [0u8; 12];
        timestamp_buf.copy_from_slice(&received.encrypted_timestamp[..12]);
        let tag = &received.encrypted_timestamp[12..];
        aead_open(&mut aead, 0, h.as_ref(), &mut timestamp_buf, tag).unwrap();
        let h = hash(&[h.as_ref(), &received.encrypted_timestamp]);

        Handshake {
            our_private: self.our_private,
            our_public: self.our_public,
            peer_public: self.peer_public,
            state: InitReceived {
                ephemeral_public_initiator,
                index_initiator: received.sender,

                constr,
                h,
            },
        }
    }

    /// Initiates a handshake with the peer.
    /// The handshake packet is written to the provided buffer.
    ///
    /// # Arguments
    /// * `index` - The index of the handshake.
    /// * `preshared_key` - The preshared key to use for the handshake.
    ///
    /// # Returns
    /// A `Handshake<InitSent>` instance.
    pub fn initiate(
        self,
        sender: u32,
        ephemeral_secret: StaticSecret,
        timestamp: Tai64N,
        cookies: &Generator,
        buf: &mut [u8],
    ) -> Handshake<InitSent> {
        use HandshakeInitMsg as M;
        if buf.len() != M::MESSAGE_LENGTH {
            panic!("invalid buffer size")
        }
        buf[0] = M::MESSAGE_TYPE;
        buf[1..4].fill(0);
        buf[M::SENDER].copy_from_slice(&sender.to_le_bytes());

        let constr = INITIAL_CONSTR_HASH;
        let h = hash(&[INITIAL_IDENTIFIER_HASH, self.peer_public.as_ref()]);
        let ephemeral_public_key = PublicKey::from(&ephemeral_secret);
        buf[M::EPHEMERAL].copy_from_slice(ephemeral_public_key.as_ref());

        let [constr] = kdf::<1>(constr, ephemeral_public_key.as_ref());
        let h = hash(&[h.as_ref(), ephemeral_public_key.as_ref()]);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.peer_public);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());
        let mut aead = ChaCha20Poly1305::new(key.as_ref().into());

        buf[M::STATIC.start..M::STATIC.start + 32].copy_from_slice(self.our_public.as_ref());

        aead_seal(&mut aead, 0, h.as_ref(), &mut buf[M::STATIC]);
        let h = hash(&[h.as_ref(), &buf[M::STATIC]]);

        let shared_secret = self.our_private.diffie_hellman(&self.peer_public);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());

        buf[M::TIMESTAMP.start..M::TIMESTAMP.start + 12].copy_from_slice(&timestamp.to_bytes());
        let mut aead = ChaCha20Poly1305::new(key.as_ref().into());
        aead_seal(&mut aead, 0, h.as_ref(), &mut buf[M::TIMESTAMP]);

        let h = hash(&[h.as_ref(), &buf[M::TIMESTAMP]]);
        cookies.add_macs(&timestamp, buf);

        Handshake {
            our_private: self.our_private,
            our_public: self.our_public,
            peer_public: self.peer_public,
            state: InitSent {
                constr,
                h,

                index_initiator: sender,
                ephemeral_secret_initiator: ephemeral_secret,
            },
        }
    }
}

impl Handshake<InitReceived> {
    /// Responds to a received handshake initiator message
    pub fn respond(
        self,
        index: u32,
        ephemeral_secret: StaticSecret,
        preshared_key: Option<[u8; 32]>,
        timestamp: Tai64N,
        cookies: &Generator,
        buf: &mut [u8],
    ) -> Handshake<ReceiverEstablished> {
        use HandshakeResponseMsg as M;
        if buf.len() != M::MESSAGE_LENGTH {
            panic!("invalid buffer size")
        }
        buf[0] = M::MESSAGE_TYPE;
        buf[1..4].fill(0);
        buf[M::SENDER].copy_from_slice(&index.to_le_bytes());
        buf[M::RECEIVER].copy_from_slice(&self.state.index_initiator.to_le_bytes());

        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        buf[M::EPHEMERAL].copy_from_slice(ephemeral_public.as_ref());

        let [constr] = kdf::<1>(self.state.constr.as_ref(), ephemeral_public.as_bytes());
        let h = hash(&[self.state.h.as_ref(), ephemeral_public.as_bytes()]);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.state.ephemeral_public_initiator);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_bytes());

        let shared_secret = ephemeral_secret.diffie_hellman(&self.peer_public);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_bytes());
        let preshared_key = preshared_key.unwrap_or_default();
        let [constr, temp, key] = kdf::<3>(constr.as_ref(), &preshared_key);
        let h = hash(&[h.as_ref(), temp.as_ref()]);
        let mut cipher = ChaCha20Poly1305::new(key.as_ref().into());

        aead_seal(&mut cipher, 0, h.as_ref(), &mut buf[M::EMPTY_TAG]);
        cookies.add_macs(&timestamp, buf);
        // unused? let h = hash(&[h.as_ref(), &encrypted_empty_tag]);

        Handshake {
            our_private: self.our_private,
            our_public: self.our_public,
            peer_public: self.peer_public,
            state: ReceiverEstablished {
                constr,
                our_index: index,
                peer_index: self.state.index_initiator,
            },
        }
    }
}

impl Handshake<InitSent> {
    pub fn response_received(
        self,
        preshared_key: Option<[u8; 32]>,
        response: HandshakeResponseMsg,
    ) -> Handshake<InitiatorEstablished> {
        if response.receiver != self.state.index_initiator {
            panic!("Invalid response sender") // TODO: handle error
        }
        let ephemeral_public_receiver = response.ephemeral_public_key;
        let [constr] = kdf::<1>(
            self.state.constr.as_ref(),
            ephemeral_public_receiver.as_ref(),
        );
        let h = hash(&[self.state.h.as_ref(), ephemeral_public_receiver.as_ref()]);

        let shared_secret = self
            .state
            .ephemeral_secret_initiator
            .diffie_hellman(&ephemeral_public_receiver);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_ref());

        let shared_secret = self.our_private.diffie_hellman(&ephemeral_public_receiver);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_ref());

        let preshared_key = preshared_key.unwrap_or_default();
        let [constr, temp, key] = kdf::<3>(constr.as_ref(), &preshared_key);

        let h = hash(&[h.as_ref(), temp.as_ref()]);
        let mut cipher = ChaCha20Poly1305::new(key.as_ref().into());
        aead_open(
            &mut cipher,
            0,
            h.as_ref(),
            &mut [],
            &response.encrypted_empty_tag,
        )
        .unwrap(); // TODO: handle error

        Handshake {
            our_private: self.our_private,
            our_public: self.our_public,
            peer_public: self.peer_public,
            state: InitiatorEstablished {
                constr,
                our_index: self.state.index_initiator,
                peer_index: response.sender,
            },
        }
    }
}

impl Handshake<ReceiverEstablished> {
    /// Finishes the handshake deriving the transport data keys
    pub fn finish(self) -> Transport {
        let [data_recv, data_send] = kdf::<2>(self.state.constr.as_ref(), &[]);
        let recv_aead = ChaCha20Poly1305::new(data_recv.as_ref().into());
        let send_aead = ChaCha20Poly1305::new(data_send.as_ref().into());
        Transport::new(
            self.state.our_index,
            self.state.peer_index,
            recv_aead,
            send_aead,
        )
    }
}

impl Handshake<InitiatorEstablished> {
    /// Finishes the handshake deriving the transport data keys
    pub fn finish(self) -> Transport {
        let [data_send, data_recv] = kdf::<2>(self.state.constr.as_ref(), &[]);
        let recv_aead = ChaCha20Poly1305::new(data_recv.as_ref().into());
        let send_aead = ChaCha20Poly1305::new(data_send.as_ref().into());
        Transport::new(
            self.state.our_index,
            self.state.peer_index,
            recv_aead,
            send_aead,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::{cookies::Verifier, messages::TransportDataMsg};

    use super::*;

    #[test]
    fn test_handshake_e2e() {
        const INITIATOR: u32 = 100;
        const RECEIVER: u32 = 200;

        let sk1 = StaticSecret::random();
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random();
        let pk2 = PublicKey::from(&sk2);

        let h_init = Handshake::new(sk1, pk2);

        let hs_init = StaticSecret::random();
        let hs_resp = StaticSecret::random();

        // macs are computed using the other party's public key
        let cg_init = Generator::new(pk2.clone());
        let cv_init = Verifier::new(pk2.clone());
        let cg_resp = Generator::new(pk1.clone());
        let cv_resp = Verifier::new(pk1.clone());

        let mut init_msg = [0u8; HandshakeInitMsg::MESSAGE_LENGTH];
        let h_init = h_init.initiate(
            INITIATOR,
            hs_init,
            Tai64N::UNIX_EPOCH,
            &cg_init,
            &mut init_msg,
        );
        assert!(cv_init.verify_mac_1(&Tai64N::UNIX_EPOCH, &init_msg)); // TODO: set timestamp
        let init_msg = HandshakeInitMsg::decode(&init_msg);
        assert_eq!(init_msg.sender, INITIATOR);

        let h_resp = Handshake::new(sk2, pk1);

        let mut resp_msg = [0u8; HandshakeResponseMsg::MESSAGE_LENGTH];
        let h_resp = h_resp.receive(init_msg).respond(
            RECEIVER,
            hs_resp,
            None,
            Tai64N::UNIX_EPOCH,
            &cg_resp,
            &mut resp_msg,
        );
        assert!(cv_resp.verify_mac_1(&Tai64N::UNIX_EPOCH, &resp_msg)); // TODO: set timestamp
        let resp_msg = HandshakeResponseMsg::decode(&resp_msg);

        assert_eq!(resp_msg.sender, RECEIVER);
        assert_eq!(resp_msg.receiver, INITIATOR);

        let h_init = h_init.response_received(None, resp_msg);
        assert_eq!(h_init.state.constr, h_resp.state.constr);

        let mut t_init = h_init.finish();
        let mut t_resp = h_resp.finish();

        const INITIATOR_DATA: &[u8] = b"Hello, World!";
        let mut init_msg = [0u8; TransportDataMsg::encoded_len(INITIATOR_DATA.len())];
        t_init.send(INITIATOR_DATA, &mut init_msg);

        let init_msg = TransportDataMsg::decode(&mut init_msg);
        assert_eq!(init_msg.receiver, RECEIVER);
        assert_eq!(init_msg.counter, 0);

        let recv_data = t_resp.receive(init_msg).unwrap();
        assert_eq!(recv_data, INITIATOR_DATA);

        const RECEIVER_DATA: &[u8] = b"Goodbye, World!";
        let mut recv_msg = [0u8; TransportDataMsg::encoded_len(RECEIVER_DATA.len())];
        t_resp.send(RECEIVER_DATA, &mut recv_msg);

        let recv_msg = TransportDataMsg::decode(&mut recv_msg);
        assert_eq!(recv_msg.receiver, INITIATOR);
        assert_eq!(recv_msg.counter, 0);
    }

    #[test]
    fn test_precalculated_hash() {
        const CONSTRUCTION_STR: &'static str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
        const IDENTIFIER_STR: &'static str = "WireGuard v1 zx2c4 Jason@zx2c4.com";

        let constr = hash(&[CONSTRUCTION_STR.as_bytes()]);
        assert_eq!(
            constr.as_ref(),
            INITIAL_CONSTR_HASH,
            "construction hash mismatch"
        );
        let h = hash(&[constr.as_ref(), IDENTIFIER_STR.as_bytes()]);
        assert_eq!(
            h.as_ref(),
            INITIAL_IDENTIFIER_HASH,
            "identifier hash mismatch"
        );
    }
}
