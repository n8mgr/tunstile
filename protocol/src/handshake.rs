use core::ops::Range;

use ring::aead::{CHACHA20_POLY1305, LessSafeKey, UnboundKey};
use tai64::Tai64N;
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, ReusableSecret, StaticSecret};

use crate::keys::{PrivateKey, PublicKey};
use zeroize::ZeroizeOnDrop;

use crate::{
    AEAD_TAG_SIZE, MAC_SIZE, MessageType,
    cookies::Generator,
    crypto::{Hash256, aead_open, aead_seal, hash, init_aead, kdf},
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

// handshake init wire layout: [type(1) | reserved(3) | sender(4) | ephemeral(32) | static+tag(48) | timestamp+tag(28) | mac1(16) | mac2(16)]
const INIT_SENDER: Range<usize> = 4..8;
const INIT_EPHEMERAL_PK: Range<usize> = INIT_SENDER.end..INIT_SENDER.end + 32;
const INIT_ENCRYPTED_STATIC_PK: Range<usize> =
    INIT_EPHEMERAL_PK.end..INIT_EPHEMERAL_PK.end + 32 + AEAD_TAG_SIZE;
const INIT_ENCRYPTED_TIMESTAMP: Range<usize> =
    INIT_ENCRYPTED_STATIC_PK.end..INIT_ENCRYPTED_STATIC_PK.end + 12 + AEAD_TAG_SIZE;
const INIT_MAC1: Range<usize> =
    INIT_ENCRYPTED_TIMESTAMP.end..INIT_ENCRYPTED_TIMESTAMP.end + MAC_SIZE;
const INIT_MAC2: Range<usize> = INIT_MAC1.end..INIT_MAC1.end + MAC_SIZE;

pub const INIT_MSG_LENGTH: usize = INIT_MAC2.end;

// handshake resp wire layout: [type(1) | reserved(3) | sender(4) | receiver(4) | ephemeral(32) | empty_tag(16) | mac1(16) | mac2(16)]
const RESP_SENDER: Range<usize> = 4..8;
const RESP_RECEIVER: Range<usize> = RESP_SENDER.end..RESP_SENDER.end + 4;
const RESP_EPHEMERAL_PK: Range<usize> = RESP_RECEIVER.end..RESP_RECEIVER.end + 32;
const RESP_ENCRYPTED_EMPTY_TAG: Range<usize> =
    RESP_EPHEMERAL_PK.end..RESP_EPHEMERAL_PK.end + AEAD_TAG_SIZE;
const RESP_MAC1: Range<usize> =
    RESP_ENCRYPTED_EMPTY_TAG.end..RESP_ENCRYPTED_EMPTY_TAG.end + MAC_SIZE;
const RESP_MAC2: Range<usize> = RESP_MAC1.end..RESP_MAC1.end + MAC_SIZE;

pub const RESP_MSG_LENGTH: usize = RESP_MAC2.end;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("failed")]
    Failed,
}

#[derive(Clone)]
pub struct Handshake<S> {
    our_private: StaticSecret,
    our_public: XPublicKey,
    peer_public: XPublicKey,

    state: S,
}

// initiator state
#[derive(Clone, ZeroizeOnDrop)]
pub struct InitSent {
    index_initiator: u32,
    ephemeral_secret_initiator: ReusableSecret,

    constr: Hash256,
    h: Hash256,
}

// responder state
#[derive(ZeroizeOnDrop)]
pub struct InitReceived {
    ephemeral_public_initiator: XPublicKey,
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

impl Handshake<InitReceived> {
    /// Returns the peer's public key. It
    /// is parsed from the handshake initiation.
    pub fn peer_key(&self) -> PublicKey {
        PublicKey(self.peer_public)
    }

    /// Parses a received handshake initiator message
    ///
    /// Returns an error if the packet is not a valid handshake initiator message.
    pub fn receive(our_private: PrivateKey, packet: &mut [u8]) -> Result<Self, HandshakeError> {
        let our_private = our_private.0;
        if packet.len() < INIT_MSG_LENGTH
            || MessageType::try_from(packet[0]) != Ok(MessageType::HandshakeInit)
        {
            return Err(HandshakeError::Failed);
        }

        let sender = u32::from_le_bytes(
            packet[INIT_SENDER]
                .try_into()
                .map_err(|_| HandshakeError::Failed)?,
        );
        let ephemeral_public_key = XPublicKey::from(
            <[u8; 32]>::try_from(&packet[INIT_EPHEMERAL_PK]).map_err(|_| HandshakeError::Failed)?,
        );

        let constr = INITIAL_CONSTR_HASH;
        let our_public = XPublicKey::from(&our_private);
        let h = hash(&[INITIAL_IDENTIFIER_HASH, our_public.as_ref()]);
        let [constr] = kdf::<1>(constr, ephemeral_public_key.as_ref());
        let h = hash(&[h.as_ref(), ephemeral_public_key.as_ref()]);
        let shared_secret = our_private.diffie_hellman(&ephemeral_public_key);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());

        let static_pk_buf = &mut packet[INIT_ENCRYPTED_STATIC_PK];
        let h_temp = hash(&[h.as_ref(), static_pk_buf]); // hash is computed based on the encrypted bytes
        // decrypt in place and verify the static public key matches the peer
        aead_open(&init_aead(&key), 0, h.as_ref(), static_pk_buf)
            .map_err(|_| HandshakeError::Failed)?;

        let mut peer_public = [0u8; 32];
        peer_public.copy_from_slice(&static_pk_buf[..32]);
        let peer_public = XPublicKey::from(peer_public);
        let h = h_temp;

        let shared_secret = our_private.diffie_hellman(&peer_public);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());

        let timestamp_buf = &mut packet[INIT_ENCRYPTED_TIMESTAMP];
        let h_temp = hash(&[h.as_ref(), timestamp_buf]); // hash is computed based on the encrypted bytes
        aead_open(&init_aead(&key), 0, h.as_ref(), timestamp_buf)
            .map_err(|_| HandshakeError::Failed)?;
        let h = h_temp;

        Ok(Handshake {
            our_private,
            our_public,
            peer_public,
            state: InitReceived {
                ephemeral_public_initiator: ephemeral_public_key,
                index_initiator: sender,

                constr,
                h,
            },
        })
    }

    /// Responds to a received handshake initiator message
    ///
    /// # Arguments
    /// * `index` - The index of the handshake.
    /// * `ephemeral_secret` - The ephemeral secret to use for the handshake.
    /// * `preshared_key` - The preshared key to use for the handshake.
    /// * `timestamp` - The timestamp to use for the handshake.
    /// * `cookies` - The cookie generator to use for the handshake.
    /// * `buf` - The buffer to write the handshake packet to. It must be exactly [`RESP_MSG_LENGTH`] bytes.
    pub fn respond(
        self,
        index: u32,
        ephemeral_secret: ReusableSecret,
        preshared_key: Option<[u8; 32]>,
        timestamp: Tai64N,
        cookies: &Generator,
        buf: &mut [u8],
    ) -> Handshake<ReceiverEstablished> {
        if buf.len() != RESP_MSG_LENGTH {
            panic!("buf must be at least RESP_MSG_LENGTH bytes");
        }
        buf[0] = MessageType::HandshakeResp as u8;
        buf[1..4].fill(0);
        buf[RESP_SENDER].copy_from_slice(&index.to_le_bytes());
        buf[RESP_RECEIVER].copy_from_slice(&self.state.index_initiator.to_le_bytes());

        let ephemeral_public = XPublicKey::from(&ephemeral_secret);
        buf[RESP_EPHEMERAL_PK].copy_from_slice(ephemeral_public.as_ref());

        let [constr] = kdf::<1>(self.state.constr.as_ref(), ephemeral_public.as_bytes());
        let h = hash(&[self.state.h.as_ref(), ephemeral_public.as_bytes()]);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.state.ephemeral_public_initiator);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_bytes());

        let shared_secret = ephemeral_secret.diffie_hellman(&self.peer_public);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_bytes());
        let preshared_key = preshared_key.unwrap_or_default();
        let [constr, temp, key] = kdf::<3>(constr.as_ref(), &preshared_key);
        let h = hash(&[h.as_ref(), temp.as_ref()]);

        aead_seal(
            &init_aead(&key),
            0,
            h.as_ref(),
            &mut buf[RESP_ENCRYPTED_EMPTY_TAG],
        );
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
    /// Initiates a handshake with the peer.
    /// The handshake packet is written to the provided buffer.
    ///
    /// # Arguments
    /// * `sender` - The index of the handshake.
    /// * `ephemeral_secret` - The ephemeral secret to use for the handshake.
    /// * `timestamp` - The timestamp to use for the handshake.
    /// * `cookies` - The cookie generator to use for the handshake.
    /// * `buf` - The buffer to write the handshake packet to. It must be exactly [`INIT_MSG_LENGTH`] bytes.
    ///
    /// # Returns
    /// A `Handshake<InitSent>` instance.
    pub fn initiate(
        our_private: PrivateKey,
        peer_public: PublicKey,
        sender: u32,
        ephemeral_secret: ReusableSecret,
        timestamp: Tai64N,
        cookies: &Generator,
        buf: &mut [u8],
    ) -> Self {
        if buf.len() != INIT_MSG_LENGTH {
            panic!("buf must be at least INIT_MSG_LENGTH bytes");
        }
        let our_private = our_private.0;
        let peer_public = peer_public.0;
        buf[0] = MessageType::HandshakeInit as u8;
        buf[1..4].fill(0);
        buf[INIT_SENDER].copy_from_slice(&sender.to_le_bytes());

        let constr = INITIAL_CONSTR_HASH;
        let h = hash(&[INITIAL_IDENTIFIER_HASH, peer_public.as_ref()]);
        let ephemeral_public_key = XPublicKey::from(&ephemeral_secret);
        buf[INIT_EPHEMERAL_PK].copy_from_slice(ephemeral_public_key.as_ref());

        let [constr] = kdf::<1>(constr, ephemeral_public_key.as_ref());
        let h = hash(&[h.as_ref(), ephemeral_public_key.as_ref()]);
        let shared_secret = ephemeral_secret.diffie_hellman(&peer_public);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());
        let aead = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, key.as_ref())
                .map_err(|_| ())
                .expect("encryption failed"),
        );

        let our_public = XPublicKey::from(&our_private);
        buf[INIT_ENCRYPTED_STATIC_PK.start..INIT_ENCRYPTED_STATIC_PK.end - AEAD_TAG_SIZE]
            .copy_from_slice(our_public.as_ref());

        aead_seal(&aead, 0, h.as_ref(), &mut buf[INIT_ENCRYPTED_STATIC_PK]);
        let h = hash(&[h.as_ref(), &buf[INIT_ENCRYPTED_STATIC_PK]]);

        let shared_secret = our_private.diffie_hellman(&peer_public);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());

        buf[INIT_ENCRYPTED_TIMESTAMP.start..INIT_ENCRYPTED_TIMESTAMP.end - AEAD_TAG_SIZE]
            .copy_from_slice(&timestamp.to_bytes());
        let aead = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, key.as_ref()).expect("encryption failed"),
        );
        aead_seal(&aead, 0, h.as_ref(), &mut buf[INIT_ENCRYPTED_TIMESTAMP]);

        let h = hash(&[h.as_ref(), &buf[INIT_ENCRYPTED_TIMESTAMP]]);
        cookies.add_macs(&timestamp, buf);

        Handshake {
            our_private,
            our_public,
            peer_public,
            state: InitSent {
                constr,
                h,

                index_initiator: sender,
                ephemeral_secret_initiator: ephemeral_secret,
            },
        }
    }

    /// Handles a received handshake response message
    ///
    /// # Arguments
    /// * `preshared_key` - The optional preshared key to use for the handshake.
    /// * `packet` - The buffer containing the handshake packet.
    ///
    /// # Returns
    /// An error if the handshake failed, otherwise a [`Handshake<InitiatorEstablished>`].
    pub fn response_received(
        self,
        preshared_key: Option<[u8; 32]>,
        packet: &mut [u8],
    ) -> Result<Handshake<InitiatorEstablished>, HandshakeError> {
        if packet.len() != RESP_MSG_LENGTH
            || MessageType::try_from(packet[0]) != Ok(MessageType::HandshakeResp)
        {
            return Err(HandshakeError::Failed);
        }

        let sender = u32::from_le_bytes(
            packet[RESP_SENDER]
                .try_into()
                .map_err(|_| HandshakeError::Failed)?,
        );
        let receiver = u32::from_le_bytes(
            packet[RESP_RECEIVER]
                .try_into()
                .map_err(|_| HandshakeError::Failed)?,
        );
        let ephemeral_public_key = XPublicKey::from(
            <[u8; 32]>::try_from(&packet[RESP_EPHEMERAL_PK]).map_err(|_| HandshakeError::Failed)?,
        );

        if receiver != self.state.index_initiator {
            return Err(HandshakeError::Failed);
        }
        let [constr] = kdf::<1>(self.state.constr.as_ref(), ephemeral_public_key.as_ref());
        let h = hash(&[self.state.h.as_ref(), ephemeral_public_key.as_ref()]);

        let shared_secret = self
            .state
            .ephemeral_secret_initiator
            .diffie_hellman(&ephemeral_public_key);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_ref());

        let shared_secret = self.our_private.diffie_hellman(&ephemeral_public_key);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_ref());

        let preshared_key = preshared_key.unwrap_or_default();
        let [constr, temp, key] = kdf::<3>(constr.as_ref(), &preshared_key);

        let h = hash(&[h.as_ref(), temp.as_ref()]);
        aead_open(
            &init_aead(&key),
            0,
            h.as_ref(),
            &mut packet[RESP_ENCRYPTED_EMPTY_TAG],
        )
        .map_err(|_| HandshakeError::Failed)?;

        Ok(Handshake {
            our_private: self.our_private,
            our_public: self.our_public,
            peer_public: self.peer_public,
            state: InitiatorEstablished {
                constr,
                our_index: self.state.index_initiator,
                peer_index: sender,
            },
        })
    }
}

impl Handshake<ReceiverEstablished> {
    /// Finishes the handshake deriving the transport data keys
    pub fn finish(self) -> Transport {
        let [data_recv, data_send] = kdf::<2>(self.state.constr.as_ref(), &[]);
        let recv_aead = init_aead(&data_recv);
        let send_aead = init_aead(&data_send);
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
        let recv_aead = init_aead(&data_recv);
        let send_aead = init_aead(&data_send);
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
    extern crate alloc;

    use crate::{cookies::Verifier, transport};
    use alloc::vec;

    use super::*;

    #[test]
    fn test_handshake_e2e() {
        const INITIATOR: u32 = 100;
        const RECEIVER: u32 = 200;

        let sk1 = PrivateKey::random();
        let pk1 = sk1.public_key();
        let sk2 = PrivateKey::random();
        let pk2 = sk2.public_key();

        let hs_init = ReusableSecret::random();
        let hs_resp = ReusableSecret::random();

        // macs are computed using the other party's public key
        let cg_init = Generator::new(pk2.clone());
        let cv_init = Verifier::new(pk2.clone());
        let cg_resp = Generator::new(pk1.clone());
        let cv_resp = Verifier::new(pk1.clone());

        let mut init_msg = [0u8; INIT_MSG_LENGTH];
        let h_init = Handshake::initiate(
            sk1,
            pk2,
            INITIATOR,
            hs_init,
            Tai64N::UNIX_EPOCH,
            &cg_init,
            &mut init_msg,
        );
        assert!(cv_init.verify_mac_1(&Tai64N::UNIX_EPOCH, &init_msg)); // TODO: set timestamp
        assert_eq!(init_msg[0], MessageType::HandshakeInit as u8);
        assert_eq!(init_msg[INIT_SENDER], INITIATOR.to_le_bytes());

        let mut resp_msg = [0u8; RESP_MSG_LENGTH];
        let h_resp = Handshake::receive(sk2, &mut init_msg).expect("receive init failed");
        assert_eq!(h_resp.peer_key(), pk1);
        let h_resp = h_resp.respond(
            RECEIVER,
            hs_resp,
            None,
            Tai64N::UNIX_EPOCH,
            &cg_resp,
            &mut resp_msg,
        );
        assert!(cv_resp.verify_mac_1(&Tai64N::UNIX_EPOCH, &resp_msg)); // TODO: set timestamp
        assert_eq!(resp_msg[0], MessageType::HandshakeResp as u8);
        assert_eq!(
            resp_msg[RESP_RECEIVER],
            INITIATOR.to_le_bytes(),
            "receiver field should be set to INITIATOR"
        );
        assert_eq!(
            resp_msg[RESP_SENDER],
            RECEIVER.to_le_bytes(),
            "sender field should be set to RECEIVER"
        );

        let h_init = h_init
            .response_received(None, &mut resp_msg)
            .expect("valid response");
        assert_eq!(h_init.state.constr, h_resp.state.constr);

        let t_init = h_init.finish();
        let t_resp = h_resp.finish();

        const INITIATOR_DATA: &[u8] = b"Hello, World!";

        let mut init_msg = vec![0u8; Transport::packet_len(INITIATOR_DATA.len())];
        t_init.send(INITIATOR_DATA, &mut init_msg);
        assert_eq!(init_msg[0], MessageType::Data as u8);
        assert_eq!(init_msg[transport::DATA_RECEIVER], RECEIVER.to_le_bytes());
        assert_eq!(init_msg[transport::DATA_COUNTER], 0u64.to_le_bytes());

        let init_payload = t_resp.receive(&mut init_msg).expect("valid init data");
        assert_eq!(init_payload, (0, INITIATOR_DATA));

        const RECEIVER_DATA: &[u8] = b"Goodbye, World!";
        let mut recv_msg = vec![0u8; Transport::packet_len(RECEIVER_DATA.len())];
        t_resp.send(RECEIVER_DATA, &mut recv_msg);
        assert_eq!(recv_msg[0], MessageType::Data as u8);
        assert_eq!(recv_msg[transport::DATA_RECEIVER], INITIATOR.to_le_bytes());
        assert_eq!(recv_msg[transport::DATA_COUNTER], 0u64.to_le_bytes());

        let recv_payload = t_init.receive(&mut recv_msg).expect("valid recv data");
        assert_eq!(recv_payload, (0, RECEIVER_DATA));
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
