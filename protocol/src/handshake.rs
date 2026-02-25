use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use tai64::Tai64N;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::{
    cookies::Generator,
    crypto::{Hash256, aead_open, aead_seal, hash, kdf},
    messages::{HandshakeInitMsg, HandshakeResponseMsg, MessageWriter},
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
        mw: &mut impl MessageWriter,
    ) -> Handshake<InitSent> {
        let constr = INITIAL_CONSTR_HASH;
        let h = hash(&[INITIAL_IDENTIFIER_HASH, self.peer_public.as_ref()]);
        let ephemeral_public_key = PublicKey::from(&ephemeral_secret);

        let [constr] = kdf::<1>(constr, ephemeral_public_key.as_ref());
        let h = hash(&[h.as_ref(), ephemeral_public_key.as_ref()]);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.peer_public);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());
        let mut aead = ChaCha20Poly1305::new(key.as_ref().into());

        let mut encrypted_static_public_key = [0u8; 32 + 16];
        encrypted_static_public_key[..32].copy_from_slice(self.our_public.as_ref());

        aead_seal(&mut aead, 0, h.as_ref(), &mut encrypted_static_public_key);
        let h = hash(&[h.as_ref(), encrypted_static_public_key.as_ref()]);

        let shared_secret = self.our_private.diffie_hellman(&self.peer_public);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());

        let mut encrypted_timestamp = [0u8; 12 + 16];
        encrypted_timestamp[..12].copy_from_slice(&timestamp.to_bytes());
        let mut aead = ChaCha20Poly1305::new(key.as_ref().into());
        aead_seal(&mut aead, 0, h.as_ref(), &mut encrypted_timestamp);

        let h = hash(&[h.as_ref(), encrypted_timestamp.as_ref()]);
        let msg = HandshakeInitMsg {
            sender,
            ephemeral_public_key,
            encrypted_static_public_key,
            encrypted_timestamp,
            mac_1: [0u8; 16],
            mac_2: [0u8; 16],
        };
        let mut msg = msg.encode();
        cookies.add_macs(&timestamp, &mut msg);
        mw.write_message(&msg);

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
        mw: &mut impl MessageWriter,
    ) -> Handshake<ReceiverEstablished> {
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

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

        let mut encrypted_empty_tag = [0u8; 16];
        aead_seal(&mut cipher, 0, h.as_ref(), &mut encrypted_empty_tag);
        // unused? let h = hash(&[h.as_ref(), &encrypted_empty_tag]);

        let hrm = HandshakeResponseMsg {
            sender: index,
            receiver: self.state.index_initiator,
            ephemeral_public_key: ephemeral_public,
            encrypted_empty_tag,
            mac_1: [0u8; 16],
            mac_2: [0u8; 16],
        };
        let mut msg = hrm.encode();
        cookies.add_macs(&timestamp, &mut msg);
        mw.write_message(&msg);

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
    use super::*;

    struct TestWriter {
        init: Option<HandshakeInitMsg>,
        response: Option<HandshakeResponseMsg>,
    }

    impl MessageWriter for TestWriter {
        fn write_message(&mut self, msg: &[u8]) {
            match msg[0] {
                HandshakeInitMsg::MESSAGE_TYPE => {
                    self.init = Some(HandshakeInitMsg::decode(msg.try_into().unwrap()));
                }
                HandshakeResponseMsg::MESSAGE_TYPE => {
                    self.response = Some(HandshakeResponseMsg::decode(msg.try_into().unwrap()));
                }
                _ => {
                    panic!("unknown message type")
                }
            }
        }
    }

    #[test]
    fn test_handshake_e2e() {
        const INITIATOR: u32 = 100;
        const RECEIVER: u32 = 200;

        let sk1 = StaticSecret::random();
        let pk1 = PublicKey::from(&sk1);
        let sk2 = StaticSecret::random();
        let pk2 = PublicKey::from(&sk2);

        let h_init = Handshake::new(sk1, pk2);

        let mut writer = TestWriter {
            init: None,
            response: None,
        };

        let hs_init = StaticSecret::random();
        let hs_resp = StaticSecret::random();

        // macs are computed using the other party's public key
        let c_init = Generator::new(pk2.clone());
        let c_resp = Generator::new(pk1.clone());

        let h_init = h_init.initiate(INITIATOR, hs_init, Tai64N::UNIX_EPOCH, &c_init, &mut writer);

        let init_msg = writer.init.take().expect("init packet set");
        assert_eq!(init_msg.sender, INITIATOR);

        let h_resp = Handshake::new(sk2, pk1);
        let h_resp = h_resp.receive(init_msg).respond(
            RECEIVER,
            hs_resp,
            None,
            Tai64N::UNIX_EPOCH,
            &c_resp,
            &mut writer,
        );

        let resp_msg = writer.response.take().expect("response packet set");
        assert_eq!(resp_msg.sender, RECEIVER);
        assert_eq!(resp_msg.receiver, INITIATOR);

        let h_init = h_init.response_received(None, resp_msg);
        assert_eq!(h_init.state.constr, h_resp.state.constr);

        let mut t_init = h_init.finish();
        let mut t_resp = h_resp.finish();

        const INITIATOR_DATA: &[u8] = b"Hello, World!";
        let mut packet_data = [0u8; INITIATOR_DATA.len() + 16];
        packet_data[..INITIATOR_DATA.len()].copy_from_slice(INITIATOR_DATA);
        let msg = t_init.seal(&mut packet_data);
        assert_eq!(msg.receiver, RECEIVER);
        assert_eq!(msg.counter, 0);

        let recv_data = t_resp.open(msg).unwrap();
        assert_eq!(recv_data, INITIATOR_DATA);

        const RECEIVER_DATA: &[u8] = b"Goodbye, World!";
        packet_data[..RECEIVER_DATA.len()].copy_from_slice(RECEIVER_DATA);
        let msg = t_resp.seal(&mut packet_data);
        assert_eq!(msg.receiver, INITIATOR);
        assert_eq!(msg.counter, 0);
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
