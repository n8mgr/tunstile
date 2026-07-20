//! Sans-IO WireGuard peer state.
//!
//! [`Peer`] holds what a driver cannot reconstruct for itself: handshake
//! crypto state, session rotation with confirm-on-first-packet semantics, replay windows,
//! and endpoint roaming. It also enforces the safety rules — an expired
//! session is unusable and replayed counters are rejected — via the `now`
//! parameters.
//!
//! Liveness is the driver's job: it initiates every handshake (and owns the
//! retransmit/abandon schedule), decides when to rekey and send keepalives,
//! and supplies indices, ephemeral secrets, and timestamps at the two calls
//! that create handshake messages. The spec's timer constants are exported
//! for drivers; sloppy (second-granularity) scheduling is fine — the spec
//! itself jitters retransmit timing.

use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use tai64::Tai64N;
use thiserror::Error;
use x25519_dalek::ReusableSecret;

use crate::{
    MessageHeader,
    cookies::{COOKIE_REPLY_LENGTH, Generator, Verifier},
    handshake::{self, Handshake, InitReceived, InitSent},
    keys::{PrivateKey, PublicKey},
    time::Instant,
    transport::{ReplayFilter, Transport},
};

/// Handshake retransmission interval.
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// Give up retransmitting a handshake after this long.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// An initiator rekeys when sending on a session older than this.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// A session refuses to encrypt or decrypt once older than this.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// Received data must be answered within this window, with a keepalive if
/// nothing else.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Above this inbound-handshake rate, [`LoadGuard`] demands a cookie before
/// CPU is spent on a handshake.
pub const MAX_HANDSHAKES_PER_SECOND: u32 = 25;
/// Drivers should rotate the [`LoadGuard`] secret this often.
pub const COOKIE_SECRET_ROTATION: Duration = Duration::from_secs(120);

/// Error from driving a [`Peer`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PeerError {
    #[error("no matching session or pending handshake")]
    Unexpected,

    #[error("handshake failed")]
    Handshake,

    #[error("invalid packet")]
    Invalid,

    #[error("replayed counter")]
    Replay,

    #[error("session expired")]
    Expired,

    #[error("no endpoint")]
    NoEndpoint,

    #[error("no session")]
    NoSession,

    #[error("send counter exhausted")]
    CounterExhausted,

    #[error("buffer too small: need {required} bytes")]
    BufferTooSmall { required: usize },

    #[error("stale handshake timestamp")]
    StaleTimestamp,

    #[error("invalid cookie reply")]
    Cookie,
}

/// Driver-supplied inputs for creating a handshake message.
pub struct HandshakeValues {
    /// A fresh random index for the new session.
    pub index: u32,

    /// A fresh ephemeral X25519 secret.
    pub ephemeral_secret: ReusableSecret,

    /// The current wall-clock time. It must exceed every timestamp
    /// previously sent to this responder or the peer rejects the
    /// initiation as a replay.
    pub timestamp: Tai64N,
}

/// A decrypted transport message from [`Peer::decrypt`].
pub struct Recv<'p> {
    /// The plaintext; empty for a keepalive.
    pub payload: &'p [u8],

    /// True when this packet confirmed a responder session, making it the
    /// send session: staged payloads can be flushed.
    pub confirmed: bool,

    /// A receiver index that no longer routes to this peer, retired by the
    /// session rotation.
    pub unmapped: Option<u32>,
}

struct Session {
    transport: Transport,
    established: Instant,
    replay: ReplayFilter,
}

impl Session {
    fn new(transport: Transport, now: Instant) -> Self {
        Self {
            transport,
            established: now,
            replay: ReplayFilter::new(),
        }
    }

    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.established) >= REJECT_AFTER_TIME
    }
}

struct PendingHandshake {
    state: Handshake<InitSent>,
    our_index: u32,
}

/// The per-peer protocol state.
pub struct Peer {
    our_key: PrivateKey,
    peer_key: PublicKey,
    endpoint: Option<SocketAddr>,

    cookie_generator: Generator,

    preshared_key: Option<[u8; 32]>,
    last_handshake_timestamp: Option<Tai64N>,

    pending: Option<PendingHandshake>,
    // send session; initiator-established sessions land here directly
    current: Option<Session>,
    // responder-established session awaiting its first authenticated packet
    next: Option<Session>,
    // receive-only grace for packets in flight across a rekey
    previous: Option<Session>,
}

impl Peer {
    /// A peer with no endpoint; it can only respond to inbound handshakes
    /// until [`Peer::set_endpoint`] gives it one.
    pub fn new(our_key: PrivateKey, peer_key: PublicKey) -> Self {
        Self {
            our_key,
            peer_key,
            endpoint: None,
            cookie_generator: Generator::new(peer_key),
            preshared_key: None,
            last_handshake_timestamp: None,
            pending: None,
            current: None,
            next: None,
            previous: None,
        }
    }

    /// Sets the optional pre-shared key.
    pub fn preshared_key(mut self, preshared_key: [u8; 32]) -> Self {
        self.preshared_key = Some(preshared_key);
        self
    }

    /// The peer's public key.
    pub fn peer_key(&self) -> PublicKey {
        self.peer_key
    }

    /// The address outbound packets are sent to, updated to the source of
    /// every authenticated inbound packet (roaming).
    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    /// Sets the endpoint for outbound packets.
    pub fn set_endpoint(&mut self, endpoint: SocketAddr) {
        self.endpoint = Some(endpoint);
    }

    /// Writes a handshake initiation (exactly
    /// [`INIT_MSG_LENGTH`](handshake::INIT_MSG_LENGTH) bytes) into `out`,
    /// addressed with `values.index`. Replaces any pending handshake and
    /// returns its index, which no longer routes to this peer. The driver
    /// owns the retransmit and abandonment schedule: call again to retransmit
    /// (each call is a fresh initiation), [`Peer::abandon_handshake`] to give
    /// up.
    pub fn initiate(
        &mut self,
        values: HandshakeValues,
        out: &mut [u8],
    ) -> Result<Option<u32>, PeerError> {
        if out.len() < handshake::INIT_MSG_LENGTH {
            return Err(PeerError::BufferTooSmall {
                required: handshake::INIT_MSG_LENGTH,
            });
        }
        let state = Handshake::initiate(
            self.our_key.clone(),
            self.peer_key,
            values.index,
            values.ephemeral_secret,
            values.timestamp,
            &mut self.cookie_generator,
            out,
        )
        .map_err(|_| PeerError::Handshake)?;
        Ok(self
            .pending
            .replace(PendingHandshake {
                state,
                our_index: values.index,
            })
            .map(|old| old.our_index))
    }

    /// Drops the pending handshake (the driver gave up retransmitting),
    /// returning its index, which no longer routes to this peer.
    pub fn abandon_handshake(&mut self) -> Option<u32> {
        self.pending.take().map(|pending| pending.our_index)
    }

    /// Responds to a parsed handshake initiation: writes the response
    /// (exactly [`RESP_MSG_LENGTH`](handshake::RESP_MSG_LENGTH) bytes,
    /// addressed with `values.index`) into `out` for the driver to send to
    /// `source`, installs the responder session (usable once the peer's
    /// first authenticated packet confirms it), and adopts `source` as the
    /// endpoint. Returns the index of a displaced unconfirmed session, which
    /// no longer routes to this peer.
    pub fn respond(
        &mut self,
        now: Instant,
        handshake: Handshake<InitReceived>,
        values: HandshakeValues,
        source: SocketAddr,
        out: &mut [u8],
    ) -> Result<Option<u32>, PeerError> {
        let received_timestamp = handshake.timestamp();
        if self
            .last_handshake_timestamp
            .is_some_and(|last| received_timestamp <= last)
        {
            return Err(PeerError::StaleTimestamp);
        }
        if out.len() < handshake::RESP_MSG_LENGTH {
            return Err(PeerError::BufferTooSmall {
                required: handshake::RESP_MSG_LENGTH,
            });
        }
        let transport = handshake
            .respond(
                values.index,
                values.ephemeral_secret,
                self.preshared_key,
                values.timestamp,
                &mut self.cookie_generator,
                out,
            )
            .map_err(|_| PeerError::Handshake)?
            .finish();
        self.last_handshake_timestamp = Some(received_timestamp);
        self.endpoint = Some(source);
        Ok(self
            .next
            .replace(Session::new(transport, now))
            .map(|old| old.transport.our_index()))
    }

    /// Handles a handshake response to our pending initiation. On success
    /// the session is adopted for sending — staged payloads can be flushed,
    /// and an initiator with nothing staged should confirm the session to
    /// the responder with a keepalive. Returns the index retired by the
    /// rotation, if any. An invalid response leaves the pending handshake
    /// (and its retransmit schedule) intact.
    pub fn handshake_response(
        &mut self,
        now: Instant,
        packet: &mut [u8],
        source: SocketAddr,
    ) -> Result<Option<u32>, PeerError> {
        let Some(pending) = self.pending.as_ref() else {
            return Err(PeerError::Unexpected);
        };
        let established = pending
            .state
            .clone()
            .response_received(self.preshared_key, packet)
            .map_err(|_| PeerError::Handshake)?;
        self.pending = None;
        Ok(self.adopt_current(Session::new(established.finish(), now), source))
    }

    /// Handles a cookie reply to the most recently sent handshake, storing
    /// the cookie so the next initiation or response carries a valid mac2.
    /// Retransmission timing remains the driver's responsibility.
    pub fn cookie_reply(&mut self, reply: &[u8], timestamp: Tai64N) -> Result<(), PeerError> {
        self.cookie_generator
            .process_cookie_reply(reply, &timestamp)
            .map_err(|_| PeerError::Cookie)
    }

    /// Encrypts `payload` as a transport data message into `out` (which must
    /// hold [`Transport::packet_len`] bytes) and returns the packet length;
    /// send it to [`Peer::endpoint`]. An empty payload is a keepalive.
    /// Returns an error when there is no usable session, no endpoint, the
    /// session or counter has expired, or the output buffer is too small.
    pub fn encrypt(
        &mut self,
        now: Instant,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PeerError> {
        if self.endpoint.is_none() {
            return Err(PeerError::NoEndpoint);
        }
        let session = self.current.as_ref().ok_or(PeerError::NoSession)?;
        if session.expired(now) {
            return Err(PeerError::Expired);
        }
        session
            .transport
            .send(payload, out)
            .map_err(|error| match error {
                crate::transport::TransportError::CounterExhausted => PeerError::CounterExhausted,
                crate::transport::TransportError::BufferTooSmall { required } => {
                    PeerError::BufferTooSmall { required }
                }
                crate::transport::TransportError::InvalidPacket => PeerError::Invalid,
            })
    }

    /// Decrypts a transport data message addressed to `receiver`. The peer's
    /// first authenticated packet on a responder session confirms it (see
    /// [`Recv::confirmed`]).
    pub fn decrypt<'p>(
        &mut self,
        now: Instant,
        receiver: u32,
        packet: &'p mut [u8],
        source: SocketAddr,
    ) -> Result<Recv<'p>, PeerError> {
        let matches = |s: &Option<Session>| {
            s.as_ref()
                .is_some_and(|s| s.transport.our_index() == receiver)
        };
        let (session, unconfirmed) = if matches(&self.next) {
            (self.next.as_mut().unwrap(), true)
        } else if matches(&self.current) {
            (self.current.as_mut().unwrap(), false)
        } else if matches(&self.previous) {
            (self.previous.as_mut().unwrap(), false)
        } else {
            return Err(PeerError::Unexpected);
        };
        if session.expired(now) {
            return Err(PeerError::Expired);
        }
        let (counter, payload) = session
            .transport
            .receive(packet)
            .map_err(|_| PeerError::Invalid)?;
        if !session.replay.validate(counter) {
            return Err(PeerError::Replay);
        }
        self.endpoint = Some(source);
        let mut unmapped = None;
        if unconfirmed {
            let session = self.next.take().unwrap();
            unmapped = self.adopt_current(session, source);
        }
        Ok(Recv {
            payload,
            confirmed: unconfirmed,
            unmapped,
        })
    }

    /// Returns the index retired by the rotation, if any.
    fn adopt_current(&mut self, session: Session, endpoint: SocketAddr) -> Option<u32> {
        let old = core::mem::replace(&mut self.previous, self.current.take());
        self.current = Some(session);
        self.endpoint = Some(endpoint);
        old.map(|old| old.transport.our_index())
    }
}

/// What to do with an inbound handshake message, from [`LoadGuard::check`].
pub enum HandshakeDecision {
    /// Process the handshake.
    Process,
    /// Discard it.
    Drop,
    /// Send this cookie challenge back instead of processing it.
    Cookie([u8; COOKIE_REPLY_LENGTH]),
}

/// Responder-side DoS mitigation, owned by whatever reads the socket: cheap
/// mac1 rejection always, and a cookie challenge (mac2) once the inbound
/// handshake rate crosses [`MAX_HANDSHAKES_PER_SECOND`]. The driver rotates
/// the secret every [`COOKIE_SECRET_ROTATION`] via
/// [`LoadGuard::rotate_secret`].
pub struct LoadGuard {
    verifier: Verifier,
    secret: [u8; 32],
    window_start: Instant,
    handshakes: u32,
}

impl LoadGuard {
    /// A guard for handshakes addressed to `our_public`, with an initial
    /// cookie secret.
    pub fn new(our_public: PublicKey, secret: [u8; 32]) -> Self {
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
        IpAddr::V4(ip) => {
            bytes[..4].copy_from_slice(&ip.octets());
            4
        }
        IpAddr::V6(ip) => {
            bytes[..16].copy_from_slice(&ip.octets());
            16
        }
    };
    bytes[ip_len..ip_len + 2].copy_from_slice(&addr.port().to_be_bytes());
    (bytes, ip_len + 2)
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn ms(millis: u64) -> Instant {
        Instant::from_millis(millis)
    }

    fn receiver_index(packet: &[u8]) -> u32 {
        u32::from_le_bytes(packet[4..8].try_into().unwrap())
    }

    fn values(index: u32) -> HandshakeValues {
        HandshakeValues {
            index,
            ephemeral_secret: ReusableSecret::random(),
            timestamp: Tai64N::UNIX_EPOCH,
        }
    }

    /// Completes a full handshake at `now`: a initiates (index 1), b
    /// responds (index 2), a confirms with a keepalive so b's session is
    /// usable too.
    fn established_pair(now: Instant) -> (Peer, Peer) {
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(a_key.clone(), b_key.public_key());
        let mut b = Peer::new(b_key.clone(), a_key.public_key());

        a.set_endpoint(addr(2));
        let mut init = [0u8; handshake::INIT_MSG_LENGTH];
        let replaced = a.initiate(values(1), &mut init).unwrap();
        assert_eq!(replaced, None);

        let hs = Handshake::receive(b_key, &mut init).expect("valid init");
        let mut resp = [0u8; handshake::RESP_MSG_LENGTH];
        let displaced = b.respond(now, hs, values(2), addr(1), &mut resp).unwrap();
        assert_eq!(displaced, None);
        assert_eq!(b.endpoint(), Some(addr(1)));

        let retired = a
            .handshake_response(now, &mut resp, addr(2))
            .expect("valid response");
        assert_eq!(retired, None);

        // a confirms the session; b's responder session becomes current
        let mut keepalive = [0u8; Transport::packet_len(0)];
        let len = a.encrypt(now, &[], &mut keepalive).expect("session usable");
        let receiver = receiver_index(&keepalive[..len]);
        let recv = b
            .decrypt(now, receiver, &mut keepalive[..len], addr(1))
            .expect("valid keepalive");
        assert!(recv.payload.is_empty());
        assert!(recv.confirmed);
        assert_eq!(recv.unmapped, None);

        (a, b)
    }

    #[test]
    fn handshake_and_transport() {
        let now = ms(0);
        let (mut a, mut b) = established_pair(now);

        let payload = b"ping";
        let mut buf = [0u8; Transport::packet_len(4)];
        let len = a.encrypt(now, payload, &mut buf).expect("session usable");
        let receiver = receiver_index(&buf[..len]);
        let recv = b
            .decrypt(now, receiver, &mut buf[..len], addr(9))
            .expect("valid data");
        assert_eq!(recv.payload, payload);
        assert!(!recv.confirmed);
        // roaming: the authenticated packet's source becomes the endpoint
        assert_eq!(b.endpoint(), Some(addr(9)));

        let payload = b"pong";
        let mut buf = [0u8; Transport::packet_len(4)];
        let len = b.encrypt(now, payload, &mut buf).expect("session usable");
        let receiver = receiver_index(&buf[..len]);
        let recv = a
            .decrypt(now, receiver, &mut buf[..len], addr(2))
            .expect("valid data");
        assert_eq!(recv.payload, payload);
    }

    #[test]
    fn replay_rejected() {
        let now = ms(0);
        let (mut a, mut b) = established_pair(now);

        let mut buf = [0u8; Transport::packet_len(4)];
        a.encrypt(now, b"once", &mut buf).unwrap();
        let receiver = receiver_index(&buf);

        let mut first = buf;
        b.decrypt(now, receiver, &mut first, addr(1))
            .expect("first delivery");

        let mut replayed = buf;
        assert_eq!(
            b.decrypt(now, receiver, &mut replayed, addr(1)).err(),
            Some(PeerError::Replay)
        );
    }

    #[test]
    fn expired_session_unusable() {
        let start = ms(0);
        let (mut a, mut b) = established_pair(start);

        // a packet encrypted in time is rejected once the session expires
        let mut buf = [0u8; Transport::packet_len(4)];
        let len = a.encrypt(start, b"late", &mut buf).unwrap();
        let receiver = receiver_index(&buf[..len]);
        let expiry = start + REJECT_AFTER_TIME;
        assert_eq!(
            b.decrypt(expiry, receiver, &mut buf[..len], addr(1)).err(),
            Some(PeerError::Expired)
        );

        // and the expired session refuses to encrypt
        assert_eq!(
            a.encrypt(expiry, b"late", &mut buf),
            Err(PeerError::Expired)
        );
    }

    #[test]
    fn initiate_replaces_pending() {
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(a_key, b_key.public_key());
        a.set_endpoint(addr(2));

        let mut short = [0u8; handshake::INIT_MSG_LENGTH - 1];
        assert_eq!(
            a.initiate(values(6), &mut short),
            Err(PeerError::BufferTooSmall {
                required: handshake::INIT_MSG_LENGTH,
            })
        );

        let mut init = [0u8; handshake::INIT_MSG_LENGTH];
        assert_eq!(a.initiate(values(7), &mut init), Ok(None));
        // a retransmit is a fresh initiation; the old index is retired
        assert_eq!(a.initiate(values(8), &mut init), Ok(Some(7)));
        assert_eq!(a.abandon_handshake(), Some(8));
        assert_eq!(a.abandon_handshake(), None);
    }

    #[test]
    fn stale_handshake_timestamp_is_rejected() {
        let now = ms(0);
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(a_key.clone(), b_key.public_key());
        let mut b = Peer::new(b_key.clone(), a_key.public_key());
        a.set_endpoint(addr(2));

        let mut first = [0u8; handshake::INIT_MSG_LENGTH];
        a.initiate(values(1), &mut first).unwrap();
        let first = Handshake::receive(b_key.clone(), &mut first).unwrap();
        let mut response = [0u8; handshake::RESP_MSG_LENGTH];
        b.respond(now, first, values(2), addr(1), &mut response)
            .unwrap();

        let mut replay = [0u8; handshake::INIT_MSG_LENGTH];
        a.initiate(values(3), &mut replay).unwrap();
        let replay = Handshake::receive(b_key, &mut replay).unwrap();
        assert_eq!(
            b.respond(now, replay, values(4), addr(1), &mut response,)
                .err(),
            Some(PeerError::StaleTimestamp)
        );
    }

    // A forced-under-load guard cookies the first init; after cookie_reply
    // the retransmitted init carries a valid mac2 and passes.
    #[test]
    fn cookie_round_trip_under_load() {
        let now = ms(0);
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(a_key, b_key.public_key());
        let mut guard = LoadGuard::new(b_key.public_key(), [42u8; 32]);
        a.set_endpoint(addr(2));

        let mut init = [0u8; handshake::INIT_MSG_LENGTH];
        a.initiate(values(1), &mut init).unwrap();
        let reply = match guard.check(now, &init, addr(1), [7u8; 24], true) {
            HandshakeDecision::Cookie(reply) => reply,
            _ => panic!("expected a cookie challenge"),
        };

        a.cookie_reply(&reply, Tai64N::UNIX_EPOCH)
            .expect("valid cookie reply");
        a.initiate(values(2), &mut init).unwrap();
        assert!(matches!(
            guard.check(now, &init, addr(1), [8u8; 24], true),
            HandshakeDecision::Process
        ));
    }

    #[test]
    fn cookie_reply_to_response_applies_to_next_response() {
        let now = ms(0);
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(a_key.clone(), b_key.public_key());
        let mut b = Peer::new(b_key.clone(), a_key.public_key());
        let mut guard = LoadGuard::new(a_key.public_key(), [42u8; 32]);
        a.set_endpoint(addr(2));

        let mut init = [0u8; handshake::INIT_MSG_LENGTH];
        a.initiate(values(1), &mut init).unwrap();
        let received = Handshake::receive(b_key.clone(), &mut init).unwrap();
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
            HandshakeValues {
                index: 3,
                ephemeral_secret: ReusableSecret::random(),
                timestamp: later,
            },
            &mut init,
        )
        .unwrap();
        let received = Handshake::receive(b_key, &mut init).unwrap();
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
