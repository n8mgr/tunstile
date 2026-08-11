use core::{net::SocketAddr, time::Duration};

use crate::{
    MessageHeader,
    cookies::{COOKIE_REPLY_LENGTH, Verifier},
    keys::PublicKey,
    time::Instant,
};

/// Above this inbound-handshake rate, [`LoadGuard`] demands a cookie before
/// CPU is spent on a handshake.
pub const MAX_HANDSHAKES_PER_SECOND: u32 = 25;

/// Result of checking an inbound handshake message.
pub enum HandshakeDecision {
    /// Process the handshake.
    Process,
    /// Discard it.
    Drop,
    /// Send this cookie challenge back instead of processing it.
    Cookie([u8; COOKIE_REPLY_LENGTH]),
}

/// Validates handshake MACs and requires a cookie when the inbound handshake
/// rate exceeds [`MAX_HANDSHAKES_PER_SECOND`].
pub struct LoadGuard {
    verifier: Verifier,
    secret: [u8; 32],
    window_start: Instant,
    handshakes: u32,
}

impl LoadGuard {
    /// A guard for handshakes addressed to `our_public`, with an initial
    /// cookie secret.
    pub fn new(our_public: &PublicKey, secret: [u8; 32]) -> Self {
        Self {
            verifier: Verifier::new(our_public),
            secret,
            window_start: Instant::from_millis(0),
            handshakes: 0,
        }
    }

    /// Replaces the rotating cookie secret.
    pub fn rotate_secret(&mut self, secret: [u8; 32]) {
        self.secret = secret;
    }

    /// Checks an inbound handshake message. `nonce` is used only if a cookie
    /// reply is issued. `force_under_load` skips the rate threshold and
    /// always demands a cookie.
    pub fn check(
        &mut self,
        now: Instant,
        msg: &[u8],
        source: SocketAddr,
        nonce: [u8; 24],
        force_under_load: bool,
    ) -> HandshakeDecision {
        if !matches!(
            MessageHeader::try_from(msg),
            Ok(MessageHeader::HandshakeInit | MessageHeader::HandshakeResponse { .. })
        ) || !self.verifier.verify_mac_1(msg)
        {
            return HandshakeDecision::Drop;
        }
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.handshakes = 0;
        }
        self.handshakes += 1;

        let under_load = force_under_load || self.handshakes > MAX_HANDSHAKES_PER_SECOND;
        if !under_load {
            return HandshakeDecision::Process;
        }
        let (source, len) = source_bytes(source);
        let source = &source[..len];
        if self.verifier.verify_mac_2(msg, source, &self.secret) {
            return HandshakeDecision::Process;
        }
        let mut reply = [0u8; COOKIE_REPLY_LENGTH];
        if self
            .verifier
            .write_cookie_reply(msg, source, &self.secret, nonce, &mut reply)
            .is_err()
        {
            return HandshakeDecision::Drop;
        }
        HandshakeDecision::Cookie(reply)
    }
}

fn source_bytes(addr: SocketAddr) -> ([u8; 18], usize) {
    let mut bytes = [0u8; 18];
    let ip_len = match addr.ip() {
        core::net::IpAddr::V4(ip) => {
            bytes[..4].copy_from_slice(&ip.octets());
            4
        }
        core::net::IpAddr::V6(ip) => {
            bytes[..16].copy_from_slice(&ip.octets());
            16
        }
    };
    bytes[ip_len..ip_len + 2].copy_from_slice(&addr.port().to_be_bytes());
    (bytes, ip_len + 2)
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr};

    use tai64::Tai64N;
    use x25519_dalek::ReusableSecret;

    use super::*;
    use crate::{
        handshake::{self, Handshake},
        keys::PrivateKey,
        peer::{HandshakeValues, Peer},
    };

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn values(index: u32) -> HandshakeValues {
        HandshakeValues {
            index,
            ephemeral_secret: ReusableSecret::random(),
            timestamp: Tai64N::UNIX_EPOCH,
        }
    }

    #[test]
    fn cookie_round_trip_under_load() {
        let now = Instant::from_millis(0);
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(b_key.public_key());
        let mut guard = LoadGuard::new(&b_key.public_key(), [42u8; 32]);
        a.set_endpoint(addr(2));

        let mut init = [0u8; handshake::INIT_MSG_LENGTH];
        a.initiate(&a_key, values(1), &mut init).unwrap();
        let reply = match guard.check(now, &init, addr(1), [7u8; 24], true) {
            HandshakeDecision::Cookie(reply) => reply,
            _ => panic!("expected a cookie challenge"),
        };

        a.cookie_reply(&reply, Tai64N::UNIX_EPOCH)
            .expect("valid cookie reply");
        a.initiate(&a_key, values(2), &mut init).unwrap();
        assert!(matches!(
            guard.check(now, &init, addr(1), [8u8; 24], true),
            HandshakeDecision::Process
        ));
    }

    #[test]
    fn cookie_reply_to_response_applies_to_next_response() {
        let now = Instant::from_millis(0);
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(b_key.public_key());
        let mut b = Peer::new(a_key.public_key());
        let mut guard = LoadGuard::new(&a_key.public_key(), [42u8; 32]);
        a.set_endpoint(addr(2));

        let mut init = [0u8; handshake::INIT_MSG_LENGTH];
        a.initiate(&a_key, values(1), &mut init).unwrap();
        let received = Handshake::receive(&b_key, &mut init).unwrap();
        let mut response = [0u8; handshake::RESP_MSG_LENGTH];
        b.respond(now, received, values(2), addr(1), &mut response)
            .unwrap();

        let reply = match guard.check(now, &response, addr(2), [7u8; 24], true) {
            HandshakeDecision::Cookie(reply) => reply,
            _ => panic!("expected a cookie challenge"),
        };
        b.cookie_reply(&reply, Tai64N::UNIX_EPOCH)
            .expect("response cookie must not require a pending initiation");

        let later = Tai64N::UNIX_EPOCH + Duration::from_secs(1);
        a.initiate(
            &a_key,
            HandshakeValues {
                index: 3,
                ephemeral_secret: ReusableSecret::random(),
                timestamp: later,
            },
            &mut init,
        )
        .unwrap();
        let received = Handshake::receive(&b_key, &mut init).unwrap();
        b.respond(
            now,
            received,
            HandshakeValues {
                index: 4,
                ephemeral_secret: ReusableSecret::random(),
                timestamp: later,
            },
            addr(1),
            &mut response,
        )
        .unwrap();
        assert!(matches!(
            guard.check(now, &response, addr(2), [8u8; 24], true),
            HandshakeDecision::Process
        ));
    }
}
