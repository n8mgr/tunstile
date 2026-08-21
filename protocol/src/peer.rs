//! Sans-IO WireGuard peer state.
//!
//! [`Peer`] holds what a driver cannot reconstruct for itself: handshake
//! crypto state, session rotation with confirm-on-first-packet semantics, replay windows,
//! and endpoint roaming. It also enforces the safety rules — an expired
//! session is unusable and replayed counters are rejected — via the `now`
//! parameters: elapsed time on the driver's monotonic clock, measured from
//! an arbitrary epoch of its choosing.

use core::net::SocketAddr;

use tai64::Tai64N;
use thiserror::Error;
use x25519_dalek::ReusableSecret;

use crate::keys::PresharedKey;
use crate::time::Instant;
use crate::{
    cookies::Generator,
    handshake::{self, Handshake, InitReceived, InitSent},
    keys::{PrivateKey, PublicKey},
};

mod load;
mod session;

pub use load::{HandshakeDecision, LoadGuard, MAX_HANDSHAKES_PER_SECOND};
pub use session::{
    KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_AFTER_TIME_RECEIVING,
    REKEY_ATTEMPT_TIME, REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MAX,
};
use session::{Session, SessionReceiveError};

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
pub struct Recv {
    /// The length of the plaintext at the start of the packet passed to
    /// [`Peer::decrypt`]. It is zero for a keepalive.
    pub payload_len: usize,

    /// True when this packet confirmed a responder session, making it the
    /// send session: staged payloads can be flushed.
    pub confirmed: bool,

    /// A receiver index that no longer routes to this peer, retired by the
    /// session rotation.
    pub unmapped: Option<u32>,
}

struct PendingHandshake {
    state: Handshake<InitSent>,
    our_index: u32,
}

/// The per-peer protocol state.
///
/// # Example
///
/// The driver supplies the receiver index, ephemeral secret, timestamp, and
/// output buffer for each handshake attempt:
///
/// ```
/// use tunstile_protocol::handshake::INIT_MSG_LENGTH;
/// use tunstile_protocol::{
///     HandshakeValues, Peer, PeerError, PrivateKey, ReusableSecret, Tai64N,
/// };
///
/// fn write_initiation(
///     private_key: &PrivateKey,
///     peer: &mut Peer,
///     ephemeral_secret: ReusableSecret,
/// ) -> Result<[u8; INIT_MSG_LENGTH], PeerError> {
///     let mut packet = [0u8; INIT_MSG_LENGTH];
///     peer.initiate(
///         private_key,
///         HandshakeValues {
///             index: 1,
///             ephemeral_secret,
///             timestamp: Tai64N::UNIX_EPOCH,
///         },
///         &mut packet,
///     )?;
///     Ok(packet)
/// }
///
/// let private_key = PrivateKey::from([1u8; 32]);
/// let mut peer = Peer::new(PrivateKey::from([2u8; 32]).public_key());
/// peer.set_endpoint("203.0.113.1:51820".parse().unwrap());
///
/// // Supply a CSPRNG-generated `ReusableSecret`, send the returned packet to
/// // `peer.endpoint()`, and schedule a retry if needed.
/// # let _ = (&private_key, &mut peer, write_initiation);
/// ```
pub struct Peer {
    peer_key: PublicKey,
    endpoint: Option<SocketAddr>,

    cookie_generator: Generator,

    preshared_key: Option<PresharedKey>,
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
    pub fn new(peer_key: PublicKey) -> Self {
        let cookie_generator = Generator::new(&peer_key);
        Self {
            peer_key,
            endpoint: None,
            cookie_generator,
            preshared_key: None,
            last_handshake_timestamp: None,
            pending: None,
            current: None,
            next: None,
            previous: None,
        }
    }

    /// Replaces or clears the pre-shared key without discarding transport
    /// sessions or a pending handshake.
    pub fn set_preshared_key(&mut self, preshared_key: Option<PresharedKey>) {
        self.preshared_key = preshared_key;
    }

    /// The peer's public key.
    pub fn peer_key(&self) -> &PublicKey {
        &self.peer_key
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
    /// up. Pass the same `our_key` to [`Peer::handshake_response`].
    pub fn initiate(
        &mut self,
        our_key: &PrivateKey,
        values: HandshakeValues,
        out: &mut [u8],
    ) -> Result<Option<u32>, PeerError> {
        if out.len() < handshake::INIT_MSG_LENGTH {
            return Err(PeerError::BufferTooSmall {
                required: handshake::INIT_MSG_LENGTH,
            });
        }
        let state = Handshake::initiate(
            our_key,
            &self.peer_key,
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
                self.preshared_key.as_ref(),
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
            .map(|old| old.our_index()))
    }

    /// Handles a handshake response to our pending initiation. On success
    /// the session is adopted for sending — staged payloads can be flushed,
    /// and an initiator with nothing staged should confirm the session to
    /// the responder with a keepalive. Returns the index retired by the
    /// rotation, if any. An invalid response leaves the pending handshake
    /// (and its retransmit schedule) intact. `our_key` must be the key used
    /// for the pending initiation.
    pub fn handshake_response(
        &mut self,
        our_key: &PrivateKey,
        now: Instant,
        packet: &mut [u8],
        source: SocketAddr,
    ) -> Result<Option<u32>, PeerError> {
        let Some(pending) = self.pending.as_ref() else {
            return Err(PeerError::Unexpected);
        };
        let established = pending
            .state
            .response_received(our_key, self.preshared_key.as_ref(), packet)
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
    /// hold [`Transport::packet_len`](crate::transport::Transport::packet_len)
    /// bytes) and returns the packet length;
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
        let session = self.current.as_mut().ok_or(PeerError::NoSession)?;
        if session.expired(now) {
            return Err(PeerError::Expired);
        }
        session.send(payload, out).map_err(|error| match error {
            crate::transport::TransportError::CounterExhausted => PeerError::CounterExhausted,
            crate::transport::TransportError::BufferTooSmall { required } => {
                PeerError::BufferTooSmall { required }
            }
            crate::transport::TransportError::InvalidPacket => PeerError::Invalid,
        })
    }

    /// Whether the current send session reached Rekey-After-Messages.
    pub fn rekey_due_to_messages(&self) -> bool {
        self.current
            .as_ref()
            .is_some_and(Session::rekey_due_to_messages)
    }

    /// Decrypts a transport data message addressed to `receiver`. The peer's
    /// first authenticated packet on a responder session confirms it (see
    /// [`Recv::confirmed`]).
    pub fn decrypt(
        &mut self,
        now: Instant,
        receiver: u32,
        packet: &mut [u8],
        source: SocketAddr,
    ) -> Result<Recv, PeerError> {
        let matches = |s: &Option<Session>| {
            s.as_ref()
                .is_some_and(|session| session.our_index() == receiver)
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
        let payload_len = session.receive(packet).map_err(|error| match error {
            SessionReceiveError::Invalid => PeerError::Invalid,
            SessionReceiveError::Replay => PeerError::Replay,
        })?;
        self.endpoint = Some(source);
        let mut unmapped = None;
        if unconfirmed {
            let session = self.next.take().unwrap();
            unmapped = self.adopt_current(session, source);
        }
        Ok(Recv {
            payload_len,
            confirmed: unconfirmed,
            unmapped,
        })
    }

    /// Returns the index retired by the rotation, if any.
    fn adopt_current(&mut self, session: Session, endpoint: SocketAddr) -> Option<u32> {
        let old = core::mem::replace(&mut self.previous, self.current.take());
        self.current = Some(session);
        self.endpoint = Some(endpoint);
        old.map(|old| old.our_index())
    }
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr};
    use core::time::Duration;

    use super::*;
    use crate::transport::Transport;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn ms(millis: u64) -> Instant {
        Duration::from_millis(millis).into()
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
        let mut a = Peer::new(b_key.public_key());
        let mut b = Peer::new(a_key.public_key());

        a.set_endpoint(addr(2));
        let mut init = [0u8; handshake::INIT_MSG_LENGTH];
        let replaced = a.initiate(&a_key, values(1), &mut init).unwrap();
        assert_eq!(replaced, None);

        let hs = Handshake::receive(&b_key, &mut init).expect("valid init");
        let mut resp = [0u8; handshake::RESP_MSG_LENGTH];
        let displaced = b.respond(now, hs, values(2), addr(1), &mut resp).unwrap();
        assert_eq!(displaced, None);
        assert_eq!(b.endpoint(), Some(addr(1)));

        let retired = a
            .handshake_response(&a_key, now, &mut resp, addr(2))
            .expect("valid response");
        assert_eq!(retired, None);

        // a confirms the session; b's responder session becomes current
        let mut keepalive = [0u8; Transport::packet_len(0)];
        let len = a.encrypt(now, &[], &mut keepalive).expect("session usable");
        let receiver = receiver_index(&keepalive[..len]);
        let recv = b
            .decrypt(now, receiver, &mut keepalive[..len], addr(1))
            .expect("valid keepalive");
        assert_eq!(recv.payload_len, 0);
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
        assert_eq!(&buf[..recv.payload_len], payload);
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
        assert_eq!(&buf[..recv.payload_len], payload);
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

        let mut buf = [0u8; Transport::packet_len(4)];
        let len = a.encrypt(start, b"late", &mut buf).unwrap();
        let receiver = receiver_index(&buf[..len]);
        let expiry = start + REJECT_AFTER_TIME;
        assert_eq!(
            b.decrypt(expiry, receiver, &mut buf[..len], addr(1)).err(),
            Some(PeerError::Expired)
        );

        assert_eq!(
            a.encrypt(expiry, b"late", &mut buf),
            Err(PeerError::Expired)
        );
    }

    #[test]
    fn initiate_replaces_pending() {
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(b_key.public_key());
        a.set_endpoint(addr(2));

        let mut short = [0u8; handshake::INIT_MSG_LENGTH - 1];
        assert_eq!(
            a.initiate(&a_key, values(6), &mut short),
            Err(PeerError::BufferTooSmall {
                required: handshake::INIT_MSG_LENGTH,
            })
        );

        let mut init = [0u8; handshake::INIT_MSG_LENGTH];
        assert_eq!(a.initiate(&a_key, values(7), &mut init), Ok(None));
        // a retransmit is a fresh initiation; the old index is retired
        assert_eq!(a.initiate(&a_key, values(8), &mut init), Ok(Some(7)));
        assert_eq!(a.abandon_handshake(), Some(8));
        assert_eq!(a.abandon_handshake(), None);
    }

    #[test]
    fn preshared_key_update_preserves_pending_handshake() {
        let now = ms(0);
        let psk = PresharedKey::from([7u8; 32]);
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(b_key.public_key());
        let mut b = Peer::new(a_key.public_key());
        b.set_preshared_key(Some(psk.clone()));

        let mut init = [0u8; handshake::INIT_MSG_LENGTH];
        a.initiate(&a_key, values(1), &mut init).unwrap();
        a.set_preshared_key(Some(psk));

        let received = Handshake::receive(&b_key, &mut init).unwrap();
        let mut response = [0u8; handshake::RESP_MSG_LENGTH];
        b.respond(now, received, values(2), addr(1), &mut response)
            .unwrap();
        a.handshake_response(&a_key, now, &mut response, addr(2))
            .expect("the pending handshake should use the updated key");
    }

    #[test]
    fn stale_handshake_timestamp_is_rejected() {
        let now = ms(0);
        let a_key = PrivateKey::random();
        let b_key = PrivateKey::random();
        let mut a = Peer::new(b_key.public_key());
        let mut b = Peer::new(a_key.public_key());
        a.set_endpoint(addr(2));

        let mut first = [0u8; handshake::INIT_MSG_LENGTH];
        a.initiate(&a_key, values(1), &mut first).unwrap();
        let first = Handshake::receive(&b_key, &mut first).unwrap();
        let mut response = [0u8; handshake::RESP_MSG_LENGTH];
        b.respond(now, first, values(2), addr(1), &mut response)
            .unwrap();

        let mut replay = [0u8; handshake::INIT_MSG_LENGTH];
        a.initiate(&a_key, values(3), &mut replay).unwrap();
        let replay = Handshake::receive(&b_key, &mut replay).unwrap();
        assert_eq!(
            b.respond(now, replay, values(4), addr(1), &mut response,)
                .err(),
            Some(PeerError::StaleTimestamp)
        );
    }
}
