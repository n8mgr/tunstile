use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use tai64::Tai64N;
use x25519_dalek::{PublicKey, StaticSecret};

const LABEL_MAC_1: &'static str = "mac1----";
const LABEL_COOKIE: &'static str = "cookie--";

// C := HASH(Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s)
const INITIAL_CONSTR_HASH: &[u8] = &[
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54];

// H := HASH(C || WireGuard v1 zx2c4 Jason@zx2c4.com)
const INITIAL_IDENTIFIER_HASH: &[u8] = &[34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34, 147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243];

mod crypto;
use crypto::*;

mod messages;
use messages::*;

pub struct Handshake<S> {
    our_private: StaticSecret,
    our_public: PublicKey,
    peer_public: PublicKey,

    state: S,
}

// pre-init state
struct Created;

// initiator state
struct InitSent {
    index_initiator: u32,
    ephemeral_secret_initiator: StaticSecret,

    constr: [u8; 32],
    h: [u8; 32],
}

// responder state
struct InitReceived {
    ephemeral_public_initiator: PublicKey,
    index_initiator: u32,
    timestamp_initiator: Tai64N,

    constr: [u8; 32],
    h: [u8; 32],
}

struct Established {
    our_index: u32,
    peer_index: u32,

    constr: [u8; 32],
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
        let h = hash(&[
            INITIAL_IDENTIFIER_HASH,
            self.our_public.as_ref(),
        ]);
        let ephemeral_public_initiator = received.ephemeral_public_key;
        let constr = kdf::<1>(&constr, &ephemeral_public_initiator.as_ref())[0];
        let h = hash(&[h.as_ref(), ephemeral_public_initiator.as_ref()]);
        let shared_secret = self.our_private.diffie_hellman(&ephemeral_public_initiator);
        let [constr, key] = kdf::<2>(&constr, &shared_secret.as_ref());
        let mut aead = ChaCha20Poly1305::new(&key.into());

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
        let [constr, key] = kdf::<2>(&constr, &shared_secret.as_ref());
        let mut aead = ChaCha20Poly1305::new(&key.into());

        // copied because the encrypted bytes are used in the hash after open
        let mut timestamp_buf = [0u8; 12];
        timestamp_buf.copy_from_slice(&received.encrypted_timestamp[..12]);
        let tag = &received.encrypted_timestamp[12..];
        aead_open(&mut aead, 0, h.as_ref(), &mut timestamp_buf, tag).unwrap();
        let timestamp_initiator = Tai64N::from_slice(&timestamp_buf).unwrap();
        let h = hash(&[h.as_ref(), &received.encrypted_timestamp]);

        Handshake {
            our_private: self.our_private,
            our_public: self.our_public,
            peer_public: self.peer_public,
            state: InitReceived {
                ephemeral_public_initiator,
                index_initiator: received.sender,
                timestamp_initiator,

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
        index: u32,
        ephemeral_secret: StaticSecret,
        timestamp: Tai64N,
        hw: &mut impl HandshakeMessageWriter,
    ) -> Handshake<InitSent> {
        let constr = INITIAL_CONSTR_HASH;
        let h = hash(&[
            INITIAL_IDENTIFIER_HASH,
            self.peer_public.as_ref(),
        ]);
        let ephemeral_public_key = PublicKey::from(&ephemeral_secret);

        let constr = kdf::<1>(&constr, &ephemeral_public_key.as_ref())[0];
        let h = hash(&[h.as_ref(), ephemeral_public_key.as_ref()]);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.peer_public);
        let [constr, key] = kdf::<2>(&constr, shared_secret.as_ref());
        let mut aead = ChaCha20Poly1305::new(&key.into());

        let mut encrypted_static_public_key = [0u8; 32 + 16];
        encrypted_static_public_key[..32].copy_from_slice(self.our_public.as_ref());

        aead_seal(&mut aead, 0, h.as_ref(), &mut encrypted_static_public_key);
        let h = hash(&[h.as_ref(), encrypted_static_public_key.as_ref()]);

        let shared_secret = self.our_private.diffie_hellman(&self.peer_public);
        let [constr, key] = kdf::<2>(&constr, shared_secret.as_ref());

        let mut encrypted_timestamp = [0u8; 12 + 16];
        encrypted_timestamp[..12].copy_from_slice(&timestamp.to_bytes());
        let mut aead = ChaCha20Poly1305::new(&key.into());
        aead_seal(&mut aead, 0, h.as_ref(), &mut encrypted_timestamp);

        let h = hash(&[h.as_ref(), encrypted_timestamp.as_ref()]);
        hw.write_message(HandshakeMessage::Init(HandshakeInitMsg {
            sender: index,
            ephemeral_public_key,
            encrypted_static_public_key,
            encrypted_timestamp,
            mac_1: [0u8; 16],
            mac_2: [0u8; 16],
        }));

        Handshake {
            our_private: self.our_private,
            our_public: self.our_public,
            peer_public: self.peer_public,
            state: InitSent {
                constr,
                h,

                index_initiator: index,
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
        hw: &mut impl HandshakeMessageWriter,
    ) -> Handshake<Established> {
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let constr = kdf::<1>(&self.state.constr, ephemeral_public.as_bytes())[0];
        let h = hash(&[self.state.h.as_ref(), ephemeral_public.as_bytes()]);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.state.ephemeral_public_initiator);
        let constr = kdf::<1>(&constr, shared_secret.as_bytes())[0];

        let shared_secret = ephemeral_secret.diffie_hellman(&self.peer_public);
        let constr = kdf::<1>(&constr, shared_secret.as_bytes())[0];
        let preshared_key = preshared_key.unwrap_or_default();
        let [constr, temp, key] = kdf::<3>(&constr, &preshared_key);
        let h = hash(&[h.as_ref(), &temp]);
        let mut cipher = ChaCha20Poly1305::new(&key.into());

        let mut encrypted_empty_tag = [0u8; 16];
        aead_seal(&mut cipher, 0, h.as_ref(), &mut encrypted_empty_tag);
        // unused? let h = hash(&[h.as_ref(), &encrypted_empty_tag]);

        hw.write_message(HandshakeMessage::Response(HandshakeResponseMsg {
            sender: index,
            receiver: self.state.index_initiator,
            ephemeral_public_key: ephemeral_public,
            encrypted_empty_tag: encrypted_empty_tag,
            mac_1: [0u8; 16],
            mac_2: [0u8; 16],
        }));

        Handshake {
            our_private: self.our_private,
            our_public: self.our_public,
            peer_public: self.peer_public,
            state: Established {
                peer_index: self.state.index_initiator,
                our_index: index,

                constr,
            },
        }
    }
}

impl Handshake<InitSent> {
    pub fn response_received(
        self,
        preshared_key: Option<[u8; 32]>,
        response: HandshakeResponseMsg,
    ) -> Handshake<Established> {
        if response.receiver != self.state.index_initiator {
            panic!("Invalid response sender") // TODO: handle error
        }
        let ephemeral_public_receiver = response.ephemeral_public_key;
        let constr = kdf::<1>(&self.state.constr, ephemeral_public_receiver.as_ref())[0];
        let h = hash(&[&self.state.h, ephemeral_public_receiver.as_ref()]);

        let shared_secret = self
            .state
            .ephemeral_secret_initiator
            .diffie_hellman(&ephemeral_public_receiver);
        let constr = kdf::<1>(&constr, shared_secret.as_ref())[0];

        let shared_secret = self.our_private.diffie_hellman(&ephemeral_public_receiver);
        let constr = kdf::<1>(&constr, shared_secret.as_ref())[0];

        let preshared_key = preshared_key.unwrap_or_default();
        let [constr, temp, key] = kdf::<3>(&constr, &preshared_key);

        let h = hash(&[h.as_ref(), &temp]);
        let mut cipher = ChaCha20Poly1305::new(&key.into());
        aead_open(&mut cipher, 0, &h, &mut [], &response.encrypted_empty_tag).unwrap(); // TODO: handle error

        Handshake {
            our_private: self.our_private,
            our_public: self.our_public,
            peer_public: self.peer_public,
            state: Established {
                peer_index: response.sender,
                our_index: self.state.index_initiator,

                constr,
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct TestWriter {
        init: Option<HandshakeInitMsg>,
        response: Option<HandshakeResponseMsg>,
    }

    impl HandshakeMessageWriter for TestWriter {
        fn write_message(&mut self, msg: HandshakeMessage) {
            match msg {
                HandshakeMessage::Init(msg) => self.init = Some(msg),
                HandshakeMessage::Response(msg) => self.response = Some(msg),
            }
        }
    }

    #[test]
    fn test_handshake() {
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

        let h_init = h_init.initiate(100, hs_init, Tai64N::UNIX_EPOCH, &mut writer);

        let init_msg = writer.init.take().expect("init packet set");
        assert_eq!(init_msg.sender, 100);

        let h_resp = Handshake::new(sk2, pk1);
        let h_resp = h_resp
            .receive(init_msg)
            .respond(500, hs_resp, None, &mut writer);

        let resp_msg = writer.response.take().expect("response packet set");
        assert_eq!(resp_msg.sender, 500);
        assert_eq!(resp_msg.receiver, 100);

        let h_init = h_init.response_received(None, resp_msg);
        assert_eq!(h_init.state.our_index, h_resp.state.peer_index);
        assert_eq!(h_init.state.peer_index, h_resp.state.our_index);
        assert_eq!(h_init.state.constr, h_resp.state.constr);
    }

    #[test]
    fn test_precalculated_hash() {
        const CONSTRUCTION_STR: &'static str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
        const IDENTIFIER_STR: &'static str = "WireGuard v1 zx2c4 Jason@zx2c4.com";

        let constr = hash(&[CONSTRUCTION_STR.as_bytes()]);
        assert_eq!(
            constr.as_ref(),
            INITIAL_CONSTR_HASH, "construction hash mismatch");
        let h = hash(&[
            constr.as_ref(),
            IDENTIFIER_STR.as_bytes(),
        ]);
        assert_eq!(
            h.as_ref(),
            INITIAL_IDENTIFIER_HASH, "identifier hash mismatch");
    }
}
