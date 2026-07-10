use core::{ops::Range, time::Duration};

use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use subtle::ConstantTimeEq;
use tai64::Tai64N;
use thiserror::Error;

use crate::crypto::{Hash256, hash, mac, xaead_open, xaead_seal};
use crate::keys::PublicKey;
use crate::{MAC_SIZE, MessageType};

const LABEL_MAC_1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";
const COOKIE_REFRESH_INTERVAL: Duration = Duration::from_secs(120);

const COOKIE_SIZE: usize = 16;
// cookie reply layout: [type(1) | reserved(3) | receiver(4) | nonce(24) | cookie+tag(32)]
const CR_RECEIVER: Range<usize> = 4..8;
const CR_NONCE: Range<usize> = 8..32;
const CR_COOKIE: Range<usize> = 32..32 + COOKIE_SIZE;
const CR_ENCRYPTED: Range<usize> = 32..64;
pub const COOKIE_REPLY_LENGTH: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CookieError {
    #[error("invalid cookie reply")]
    Invalid,
}

fn mac1_offset(msg: &[u8]) -> usize {
    msg.len() - 2 * MAC_SIZE
}

fn mac2_offset(msg: &[u8]) -> usize {
    msg.len() - MAC_SIZE
}

struct LastCookie {
    received_timestamp: Tai64N,
    cookie: [u8; COOKIE_SIZE],
}

/// Writes the outgoing MACs on handshake messages to a peer, and consumes the
/// cookie replies that peer sends back when it is under load.
pub struct Generator {
    mac1_key: Hash256,
    cookie_key: Hash256,
    last_cookie: Option<LastCookie>,
}

impl Generator {
    /// Creates a generator for handshakes addressed to `public_key`.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            mac1_key: hash(&[LABEL_MAC_1, public_key.as_bytes()]),
            cookie_key: hash(&[LABEL_COOKIE, public_key.as_bytes()]),
            last_cookie: None,
        }
    }

    /// Writes mac1, and mac2 if a fresh cookie is held, into the trailing MAC
    /// fields of a handshake message.
    pub fn add_macs(&self, current_timestamp: &Tai64N, msg: &mut [u8]) {
        let mac_1_offset = mac1_offset(msg);
        let mac_2_offset = mac2_offset(msg);

        let mac_1 = mac(self.mac1_key.as_ref(), &[&msg[..mac_1_offset]]);
        msg[mac_1_offset..mac_2_offset].copy_from_slice(&mac_1);

        if let Some(last_cookie) = self.last_cookie.as_ref()
            && current_timestamp
                .duration_since(&last_cookie.received_timestamp)
                .unwrap_or_default()
                <= COOKIE_REFRESH_INTERVAL
        {
            let mac_2 = mac(&last_cookie.cookie, &[&msg[..mac_2_offset]]);
            msg[mac_2_offset..].copy_from_slice(&mac_2);
        }
    }

    /// Decrypts a cookie reply the peer sent in response to a handshake and
    /// stores the cookie so subsequent handshakes carry a valid mac2.
    /// `sent_mac1` is the mac1 of the handshake that prompted the reply.
    pub fn process_cookie_reply(
        &mut self,
        reply: &[u8],
        sent_mac1: &[u8],
        now: &Tai64N,
    ) -> Result<(), CookieError> {
        if reply.len() != COOKIE_REPLY_LENGTH {
            return Err(CookieError::Invalid);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.cookie_key.as_ref())
            .map_err(|_| CookieError::Invalid)?;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&reply[CR_NONCE]);
        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(&reply[CR_COOKIE]);
        xaead_open(
            &cipher,
            nonce,
            sent_mac1,
            &mut cookie,
            &reply[CR_COOKIE.end..CR_ENCRYPTED.end],
        )
        .map_err(|_| CookieError::Invalid)?;
        self.last_cookie = Some(LastCookie {
            received_timestamp: *now,
            cookie,
        });
        Ok(())
    }
}

/// Verifies incoming handshake MACs (keyed on our own static key) and, when
/// under load, issues cookie replies that a peer must echo via mac2 before we
/// spend CPU on its handshake.
pub struct Verifier {
    mac1_key: Hash256,
    cookie_key: Hash256,
}

impl Verifier {
    /// Creates a verifier for handshakes addressed to our own `public_key`.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            mac1_key: hash(&[LABEL_MAC_1, public_key.as_bytes()]),
            cookie_key: hash(&[LABEL_COOKIE, public_key.as_bytes()]),
        }
    }

    /// True if the message's mac1 is valid.
    pub fn verify_mac_1(&self, msg: &[u8]) -> bool {
        let mac_1_offset = mac1_offset(msg);
        let mac_2_offset = mac2_offset(msg);
        let mac_1 = mac(self.mac1_key.as_ref(), &[&msg[..mac_1_offset]]);
        mac_1.ct_eq(&msg[mac_1_offset..mac_2_offset]).into()
    }

    /// The cookie a source address should be presenting, given the current
    /// rotating secret. Callers rotate `secret` every [`COOKIE_REFRESH_INTERVAL`].
    fn cookie(source: &[u8], secret: &[u8; 32]) -> [u8; COOKIE_SIZE] {
        mac(secret, &[source])
    }

    /// True if `msg` carries a mac2 matching the cookie we would have issued
    /// to `source`. A message from a peer that has never been cookied (mac2
    /// all zero) fails this, which is the point: it must round-trip a reply.
    pub fn verify_mac_2(&self, msg: &[u8], source: &[u8], secret: &[u8; 32]) -> bool {
        let mac_2 = mac(&Self::cookie(source, secret), &[&msg[..mac2_offset(msg)]]);
        mac_2.ct_eq(&msg[mac2_offset(msg)..]).into()
    }

    /// Writes a cookie reply for the handshake in `prompting`, encrypting the
    /// cookie for `source` under a caller-supplied `nonce`. `out` must be
    /// [`COOKIE_REPLY_LENGTH`] bytes.
    pub fn write_cookie_reply(
        &self,
        prompting: &[u8],
        source: &[u8],
        secret: &[u8; 32],
        nonce: [u8; 24],
        out: &mut [u8],
    ) {
        let cookie = Self::cookie(source, secret);
        let mut mac_1 = [0u8; MAC_SIZE];
        let m1 = mac1_offset(prompting);
        mac_1.copy_from_slice(&prompting[m1..m1 + MAC_SIZE]);

        out[0] = MessageType::Cookie as u8;
        out[1..4].fill(0);
        out[CR_RECEIVER].copy_from_slice(&prompting[4..8]);
        out[CR_NONCE].copy_from_slice(&nonce);
        out[CR_COOKIE].copy_from_slice(&cookie);
        let cipher = XChaCha20Poly1305::new_from_slice(self.cookie_key.as_ref())
            .expect("cookie key is 32 bytes");
        xaead_seal(&cipher, nonce, &mac_1, &mut out[CR_ENCRYPTED]);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{PrivateKey, handshake::INIT_MSG_LENGTH};

    #[test]
    fn cookie_round_trip() {
        // responder identity; the initiator addresses MACs to it
        let responder = PrivateKey::random().public_key();
        let generator = &mut Generator::new(responder);
        let checker = Verifier::new(responder);

        let now = Tai64N::UNIX_EPOCH;
        let source = b"203.0.113.7:51820";
        let secret = [42u8; 32];
        let nonce = [7u8; 24];

        let mut msg = [0u8; INIT_MSG_LENGTH];
        generator.add_macs(&now, &mut msg);
        assert!(checker.verify_mac_1(&msg), "mac1 must verify");
        assert!(
            !checker.verify_mac_2(&msg, source, &secret),
            "no cookie yet: mac2 must not verify"
        );
        let sent_mac1 = msg[mac1_offset(&msg)..mac2_offset(&msg)].to_vec();

        let mut reply = [0u8; COOKIE_REPLY_LENGTH];
        checker.write_cookie_reply(&msg, source, &secret, nonce, &mut reply);

        generator
            .process_cookie_reply(&reply, &sent_mac1, &now)
            .unwrap();
        let mut msg2 = [0u8; INIT_MSG_LENGTH];
        generator.add_macs(&now, &mut msg2);
        assert!(
            checker.verify_mac_2(&msg2, source, &secret),
            "mac2 must verify after cookie"
        );
        assert!(
            !checker.verify_mac_2(&msg2, b"198.51.100.1:51820", &secret),
            "a different source must not match"
        );
    }

    #[test]
    fn cookie_reply_rejects_tampering() {
        let responder = PrivateKey::random().public_key();
        let mut generator = Generator::new(responder);
        let checker = Verifier::new(responder);
        let now = Tai64N::UNIX_EPOCH;

        let mut msg = [0u8; INIT_MSG_LENGTH];
        generator.add_macs(&now, &mut msg);
        let sent_mac1 = msg[mac1_offset(&msg)..mac2_offset(&msg)].to_vec();

        let mut reply = [0u8; COOKIE_REPLY_LENGTH];
        checker.write_cookie_reply(&msg, b"a", &[1u8; 32], [0u8; 24], &mut reply);
        reply[40] ^= 0x01;
        assert_eq!(
            generator.process_cookie_reply(&reply, &sent_mac1, &now),
            Err(CookieError::Invalid)
        );
    }
}
