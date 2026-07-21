//! The Noise IKpsk2 handshake, from initiation through transport-key
//! derivation.

use core::ops::Range;

use ring::aead::{CHACHA20_POLY1305, LessSafeKey, UnboundKey};
use tai64::Tai64N;
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, ReusableSecret, SharedSecret};
use zeroize::ZeroizeOnDrop;

use crate::{
    AEAD_TAG_SIZE, MAC_SIZE, MessageType,
    cookies::Generator,
    crypto::{Hash256, aead_open, aead_seal, hash, init_aead, kdf},
    keys::{PresharedKey, PrivateKey, PublicKey},
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

/// Wire length of a handshake initiation message.
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

/// Wire length of a handshake response message.
pub const RESP_MSG_LENGTH: usize = RESP_MAC2.end;

/// Error creating or processing a handshake message.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandshakeError {
    #[error("failed")]
    Failed,

    #[error("buffer too small: need {required} bytes")]
    BufferTooSmall { required: usize },
}

fn contributory(secret: SharedSecret) -> Result<SharedSecret, HandshakeError> {
    secret
        .was_contributory()
        .then_some(secret)
        .ok_or(HandshakeError::Failed)
}

/// A WireGuard (Noise IKpsk2) handshake, parameterized by its current state.
pub struct Handshake<S> {
    state: S,
}

/// Initiator state: an initiation was sent; awaiting the peer's response.
#[derive(ZeroizeOnDrop)]
pub struct InitSent {
    index_initiator: u32,
    ephemeral_secret_initiator: ReusableSecret,

    constr: Hash256,
    h: Hash256,
}

/// Responder state: a valid initiation was received and can be responded to.
#[derive(ZeroizeOnDrop)]
pub struct InitReceived {
    peer_public: PublicKey,
    ephemeral_public_initiator: XPublicKey,
    index_initiator: u32,
    #[zeroize(skip)]
    timestamp: Tai64N,

    constr: Hash256,
    h: Hash256,
}

/// Responder state: the response was sent; transport keys can be derived.
#[derive(ZeroizeOnDrop)]
pub struct ReceiverEstablished {
    our_index: u32,
    peer_index: u32,
    constr: Hash256,
}

/// Initiator state: a valid response was received; transport keys can be
/// derived.
#[derive(ZeroizeOnDrop)]
pub struct InitiatorEstablished {
    our_index: u32,
    peer_index: u32,
    constr: Hash256,
}

impl Handshake<InitReceived> {
    /// The peer's public key, parsed from the initiation.
    pub fn peer_key(&self) -> &PublicKey {
        &self.state.peer_public
    }

    /// The authenticated timestamp carried by the initiation.
    pub fn timestamp(&self) -> Tai64N {
        self.state.timestamp
    }

    /// Parses and validates a received handshake initiation.
    pub fn receive(our_private: &PrivateKey, packet: &mut [u8]) -> Result<Self, HandshakeError> {
        if packet.len() != INIT_MSG_LENGTH
            || MessageType::try_from(packet[0]) != Ok(MessageType::HandshakeInit)
            || packet[1..4] != [0; 3]
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
        let our_public = our_private.public_key();
        let h = hash(&[INITIAL_IDENTIFIER_HASH, our_public.as_bytes()]);
        let [constr] = kdf::<1>(constr, ephemeral_public_key.as_ref());
        let h = hash(&[h.as_ref(), ephemeral_public_key.as_ref()]);
        let shared_secret = contributory(our_private.0.diffie_hellman(&ephemeral_public_key))?;
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());

        let static_pk_buf = &mut packet[INIT_ENCRYPTED_STATIC_PK];
        let h_temp = hash(&[h.as_ref(), static_pk_buf]); // hash is computed based on the encrypted bytes
        aead_open(&init_aead(&key), 0, h.as_ref(), static_pk_buf)
            .map_err(|_| HandshakeError::Failed)?;

        let mut peer_public = [0u8; 32];
        peer_public.copy_from_slice(&static_pk_buf[..32]);
        let peer_public = PublicKey::from(peer_public);
        let h = h_temp;

        let shared_secret = contributory(our_private.0.diffie_hellman(&peer_public.0))?;
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());

        let timestamp_buf = &mut packet[INIT_ENCRYPTED_TIMESTAMP];
        let h_temp = hash(&[h.as_ref(), timestamp_buf]); // hash is computed based on the encrypted bytes
        let timestamp = Tai64N::from_slice(
            aead_open(&init_aead(&key), 0, h.as_ref(), timestamp_buf)
                .map_err(|_| HandshakeError::Failed)?,
        )
        .map_err(|_| HandshakeError::Failed)?;
        let h = h_temp;

        Ok(Handshake {
            state: InitReceived {
                peer_public,
                ephemeral_public_initiator: ephemeral_public_key,
                index_initiator: sender,
                timestamp,

                constr,
                h,
            },
        })
    }

    /// Responds to the received initiation, writing the response message to
    /// the first [`RESP_MSG_LENGTH`] bytes of `buf`.
    pub fn respond(
        self,
        index: u32,
        ephemeral_secret: ReusableSecret,
        preshared_key: Option<&PresharedKey>,
        timestamp: Tai64N,
        cookies: &mut Generator,
        buf: &mut [u8],
    ) -> Result<Handshake<ReceiverEstablished>, HandshakeError> {
        if buf.len() < RESP_MSG_LENGTH {
            return Err(HandshakeError::BufferTooSmall {
                required: RESP_MSG_LENGTH,
            });
        }
        let buf = &mut buf[..RESP_MSG_LENGTH];
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

        let shared_secret = ephemeral_secret.diffie_hellman(&self.state.peer_public.0);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_bytes());
        let default_preshared_key = PresharedKey::default();
        let preshared_key = preshared_key.unwrap_or(&default_preshared_key);
        let [constr, temp, key] = kdf::<3>(constr.as_ref(), preshared_key.as_ref());
        let h = hash(&[h.as_ref(), temp.as_ref()]);

        aead_seal(
            &init_aead(&key),
            0,
            h.as_ref(),
            &mut buf[RESP_ENCRYPTED_EMPTY_TAG],
        );
        cookies
            .add_macs(&timestamp, buf)
            .map_err(|_| HandshakeError::Failed)?;

        Ok(Handshake {
            state: ReceiverEstablished {
                constr,
                our_index: index,
                peer_index: self.state.index_initiator,
            },
        })
    }
}

impl Handshake<InitSent> {
    /// Initiates a handshake with the peer, writing the initiation message to
    /// the first [`INIT_MSG_LENGTH`] bytes of `buf`.
    pub fn initiate(
        our_private: &PrivateKey,
        peer_public: &PublicKey,
        sender: u32,
        ephemeral_secret: ReusableSecret,
        timestamp: Tai64N,
        cookies: &mut Generator,
        buf: &mut [u8],
    ) -> Result<Self, HandshakeError> {
        if buf.len() < INIT_MSG_LENGTH {
            return Err(HandshakeError::BufferTooSmall {
                required: INIT_MSG_LENGTH,
            });
        }
        let buf = &mut buf[..INIT_MSG_LENGTH];
        buf[0] = MessageType::HandshakeInit as u8;
        buf[1..4].fill(0);
        buf[INIT_SENDER].copy_from_slice(&sender.to_le_bytes());

        let constr = INITIAL_CONSTR_HASH;
        let h = hash(&[INITIAL_IDENTIFIER_HASH, peer_public.as_bytes()]);
        let ephemeral_public_key = XPublicKey::from(&ephemeral_secret);
        buf[INIT_EPHEMERAL_PK].copy_from_slice(ephemeral_public_key.as_ref());

        let [constr] = kdf::<1>(constr, ephemeral_public_key.as_ref());
        let h = hash(&[h.as_ref(), ephemeral_public_key.as_ref()]);
        let shared_secret = contributory(ephemeral_secret.diffie_hellman(&peer_public.0))?;
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());
        let aead = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, key.as_ref())
                .map_err(|_| ())
                .expect("encryption failed"),
        );

        let our_public = our_private.public_key();
        buf[INIT_ENCRYPTED_STATIC_PK.start..INIT_ENCRYPTED_STATIC_PK.end - AEAD_TAG_SIZE]
            .copy_from_slice(our_public.as_bytes());

        aead_seal(&aead, 0, h.as_ref(), &mut buf[INIT_ENCRYPTED_STATIC_PK]);
        let h = hash(&[h.as_ref(), &buf[INIT_ENCRYPTED_STATIC_PK]]);

        let shared_secret = our_private.0.diffie_hellman(&peer_public.0);
        let [constr, key] = kdf::<2>(constr.as_ref(), shared_secret.as_ref());

        buf[INIT_ENCRYPTED_TIMESTAMP.start..INIT_ENCRYPTED_TIMESTAMP.end - AEAD_TAG_SIZE]
            .copy_from_slice(&timestamp.to_bytes());
        let aead = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, key.as_ref()).expect("encryption failed"),
        );
        aead_seal(&aead, 0, h.as_ref(), &mut buf[INIT_ENCRYPTED_TIMESTAMP]);

        let h = hash(&[h.as_ref(), &buf[INIT_ENCRYPTED_TIMESTAMP]]);
        cookies
            .add_macs(&timestamp, buf)
            .map_err(|_| HandshakeError::Failed)?;

        Ok(Handshake {
            state: InitSent {
                constr,
                h,

                index_initiator: sender,
                ephemeral_secret_initiator: ephemeral_secret,
            },
        })
    }

    /// Consumes a received handshake response to our initiation, yielding the
    /// established initiator handshake. `our_private` must be the key used to
    /// create the initiation.
    pub fn response_received(
        self,
        our_private: &PrivateKey,
        preshared_key: Option<&PresharedKey>,
        packet: &mut [u8],
    ) -> Result<Handshake<InitiatorEstablished>, HandshakeError> {
        self.response_received_ref(our_private, preshared_key, packet)
    }

    pub(crate) fn response_received_ref(
        &self,
        our_private: &PrivateKey,
        preshared_key: Option<&PresharedKey>,
        packet: &mut [u8],
    ) -> Result<Handshake<InitiatorEstablished>, HandshakeError> {
        if packet.len() != RESP_MSG_LENGTH
            || MessageType::try_from(packet[0]) != Ok(MessageType::HandshakeResp)
            || packet[1..4] != [0; 3]
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

        let shared_secret = contributory(
            self.state
                .ephemeral_secret_initiator
                .diffie_hellman(&ephemeral_public_key),
        )?;
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_ref());

        let shared_secret = our_private.0.diffie_hellman(&ephemeral_public_key);
        let [constr] = kdf::<1>(constr.as_ref(), shared_secret.as_ref());

        let default_preshared_key = PresharedKey::default();
        let preshared_key = preshared_key.unwrap_or(&default_preshared_key);
        let [constr, temp, key] = kdf::<3>(constr.as_ref(), preshared_key.as_ref());

        let h = hash(&[h.as_ref(), temp.as_ref()]);
        aead_open(
            &init_aead(&key),
            0,
            h.as_ref(),
            &mut packet[RESP_ENCRYPTED_EMPTY_TAG],
        )
        .map_err(|_| HandshakeError::Failed)?;

        Ok(Handshake {
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
        let mut cg_init = Generator::new(&pk2);
        let cv_init = Verifier::new(&pk2);
        let mut cg_resp = Generator::new(&pk1);
        let cv_resp = Verifier::new(&pk1);

        let mut init_msg = [0u8; INIT_MSG_LENGTH];
        let h_init = Handshake::initiate(
            &sk1,
            &pk2,
            INITIATOR,
            hs_init,
            Tai64N::UNIX_EPOCH,
            &mut cg_init,
            &mut init_msg,
        )
        .unwrap();
        assert!(cv_init.verify_mac_1(&init_msg));
        assert_eq!(init_msg[0], MessageType::HandshakeInit as u8);
        assert_eq!(init_msg[INIT_SENDER], INITIATOR.to_le_bytes());

        let mut resp_msg = [0u8; RESP_MSG_LENGTH];
        let h_resp = Handshake::receive(&sk2, &mut init_msg).expect("receive init failed");
        assert_eq!(h_resp.peer_key(), &pk1);
        assert_eq!(h_resp.timestamp(), Tai64N::UNIX_EPOCH);
        let h_resp = h_resp
            .respond(
                RECEIVER,
                hs_resp,
                None,
                Tai64N::UNIX_EPOCH,
                &mut cg_resp,
                &mut resp_msg,
            )
            .unwrap();
        assert!(cv_resp.verify_mac_1(&resp_msg));
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
            .response_received(&sk1, None, &mut resp_msg)
            .expect("valid response");
        assert_eq!(h_init.state.constr, h_resp.state.constr);

        let t_init = h_init.finish();
        let t_resp = h_resp.finish();

        const INITIATOR_DATA: &[u8] = b"Hello, World!";

        let mut init_msg = vec![0u8; Transport::packet_len(INITIATOR_DATA.len())];
        t_init.send(INITIATOR_DATA, &mut init_msg).unwrap();
        assert_eq!(init_msg[0], MessageType::Data as u8);
        assert_eq!(init_msg[transport::DATA_RECEIVER], RECEIVER.to_le_bytes());
        assert_eq!(init_msg[transport::DATA_COUNTER], 0u64.to_le_bytes());

        let init_payload = t_resp.receive(&mut init_msg).expect("valid init data");
        assert_eq!(init_payload, (0, INITIATOR_DATA));

        const RECEIVER_DATA: &[u8] = b"Goodbye, World!";
        let mut recv_msg = vec![0u8; Transport::packet_len(RECEIVER_DATA.len())];
        t_resp.send(RECEIVER_DATA, &mut recv_msg).unwrap();
        assert_eq!(recv_msg[0], MessageType::Data as u8);
        assert_eq!(recv_msg[transport::DATA_RECEIVER], INITIATOR.to_le_bytes());
        assert_eq!(recv_msg[transport::DATA_COUNTER], 0u64.to_le_bytes());

        let recv_payload = t_init.receive(&mut recv_msg).expect("valid recv data");
        assert_eq!(recv_payload, (0, RECEIVER_DATA));
    }

    #[test]
    fn test_precalculated_hash() {
        const CONSTRUCTION_STR: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
        const IDENTIFIER_STR: &str = "WireGuard v1 zx2c4 Jason@zx2c4.com";

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

    #[test]
    fn initiate_rejects_a_non_contributory_peer_key() {
        let our_key = PrivateKey::random();
        let peer_key = PublicKey::from([0u8; 32]);
        let mut cookies = Generator::new(&peer_key);
        let mut packet = [0u8; INIT_MSG_LENGTH];

        assert!(matches!(
            Handshake::initiate(
                &our_key,
                &peer_key,
                1,
                ReusableSecret::random(),
                Tai64N::UNIX_EPOCH,
                &mut cookies,
                &mut packet,
            ),
            Err(HandshakeError::Failed)
        ));
    }

    #[test]
    fn initiate_accepts_a_larger_output_buffer() {
        let our_key = PrivateKey::random();
        let peer_key = PrivateKey::random().public_key();
        let mut cookies = Generator::new(&peer_key);
        let mut packet = [0xaau8; INIT_MSG_LENGTH + 8];

        Handshake::initiate(
            &our_key,
            &peer_key,
            1,
            ReusableSecret::random(),
            Tai64N::UNIX_EPOCH,
            &mut cookies,
            &mut packet,
        )
        .unwrap();

        assert_eq!(&packet[INIT_MSG_LENGTH..], &[0xaa; 8]);
    }
}
