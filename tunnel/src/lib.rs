//! An async WireGuard tunnel that drives [tunstile_protocol] over one UDP
//! socket. It owns peer sessions and timers but does not apply IP routing or
//! AllowedIPs policy.
//!
//! # Example
//!
//! ```no_run
//! use std::{error::Error, net::SocketAddr};
//! use tunstile_tunnel::{Peer, PeerConfig, PrivateKey, PublicKey, Tunnel};
//!
//! async fn connect(
//!     private_key: PrivateKey,
//!     peer_key: PublicKey,
//!     endpoint: SocketAddr,
//! ) -> Result<(Tunnel, Peer), Box<dyn Error>> {
//!     let tunnel = Tunnel::new("0.0.0.0:0".parse()?, private_key).await?;
//!     let peer = tunnel
//!         .add_peer(
//!             &peer_key,
//!             PeerConfig {
//!                 endpoint: Some(endpoint),
//!                 ..Default::default()
//!             },
//!         )
//!         .await?;
//!     Ok((tunnel, peer))
//! }
//! ```

use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use log::debug;
use quinn_udp::{BATCH_SIZE, RecvMeta};
use thiserror::Error;
use tokio::{spawn, task::JoinHandle};
pub use tunstile_protocol::{KeyParseError, PresharedKey, PrivateKey, PublicKey};
use tunstile_protocol::{
    MessageHeader,
    handshake::Handshake,
    peer::{COOKIE_SECRET_ROTATION, HandshakeDecision, LoadGuard},
};

mod actor;
mod peer;
mod router;
mod socket;

use actor::Clock;
pub use peer::{Peer, PeerSender};
use router::RoutingTable;
use socket::UdpSocket;

const MAX_MESSAGE_SIZE: usize = 65535;

/// Error sending to a peer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SendError {
    #[error("tunnel is closed")]
    TunnelClosed,

    #[error("peer was removed")]
    PeerRemoved,

    #[error("peer send queue is full")]
    Full,
}

/// Error registering a peer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegisterError {
    #[error("peer already registered")]
    AlreadyRegistered,
}

/// Optional settings for a peer.
#[derive(Debug, Clone, Default)]
pub struct PeerConfig {
    /// The peer's initial or replacement endpoint. When passed to
    /// [`Tunnel::set_peer`], `None` keeps the current endpoint.
    pub endpoint: Option<SocketAddr>,

    /// The optional pre-shared key.
    pub preshared_key: Option<PresharedKey>,

    /// The persistent keepalive interval.
    pub persistent_keepalive: Option<Duration>,
}

/// A point-in-time snapshot of a peer's endpoint, traffic counters, and
/// timers.
#[derive(Clone, Debug)]
pub struct PeerStatus {
    pub public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,

    pub tx_bytes: u64,
    pub rx_bytes: u64,

    pub last_send: Option<SystemTime>,
    pub last_recv: Option<SystemTime>,
    pub last_successful_handshake: Option<SystemTime>,
}

/// A WireGuard tunnel: one UDP socket multiplexing any number of registered
/// peers.
///
/// # Example
///
/// ```no_run
/// use tunstile_tunnel::{PeerConfig, PrivateKey, Tunnel};
///
/// # async fn connect() -> Result<(), Box<dyn std::error::Error>> {
/// let tunnel = Tunnel::new("0.0.0.0:0".parse()?, PrivateKey::random()).await?;
/// let peer_key = "jrpP5X9mNSxjkd6tCnHwdRI4Rp8ZnquQj34UAqlZpx8=".parse()?;
/// let mut peer = tunnel
///     .add_peer(
///         &peer_key,
///         PeerConfig {
///             endpoint: Some("203.0.113.1:51820".parse()?),
///             ..Default::default()
///         },
///     )
///     .await?;
///
/// peer.send(vec![0u8; 20]).await?;
/// let _next_packet = peer.recv().await;
/// # Ok(())
/// # }
/// ```
pub struct Tunnel {
    our_key: Arc<PrivateKey>,
    socket: Arc<UdpSocket>,
    router: Arc<RoutingTable>,
    // only the read loop's clone is read in production; the tunnel keeps a
    // handle solely so tests can force the under-load path
    #[cfg(test)]
    under_load: Arc<AtomicBool>,
    read_task: JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.read_task.abort();
    }
}

impl Tunnel {
    async fn read_loop(
        our_private: Arc<PrivateKey>,
        socket: Arc<UdpSocket>,
        router: Arc<RoutingTable>,
        under_load: Arc<AtomicBool>,
    ) {
        let clock = Clock::new();
        let mut guard = LoadGuard::new(&our_private.public_key(), rand::random());
        let mut secret_rotated = clock.now();
        let mut bufs = vec![vec![0u8; MAX_MESSAGE_SIZE]; BATCH_SIZE];
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        loop {
            let mut slices: Vec<IoSliceMut> = bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
            let n = match socket.recv(&mut slices, &mut metas).await {
                Ok(n) => n,
                Err(e) => {
                    debug!("failed to receive packets: {:?}", e);
                    continue;
                }
            };
            drop(slices);
            for (buf, meta) in bufs.iter_mut().zip(metas.iter()).take(n) {
                let mut offset = 0;
                while offset < meta.len {
                    let len = meta.stride.min(meta.len - offset);
                    if len == 0 {
                        break;
                    }
                    let segment = &mut buf[offset..offset + len];
                    offset += len;
                    let header = match MessageHeader::try_from(&*segment) {
                        Ok(header) => header,
                        Err(e) => {
                            debug!("dropping invalid packet from {}: {:?}", meta.addr, e);
                            continue;
                        }
                    };
                    if matches!(
                        header,
                        MessageHeader::HandshakeInit | MessageHeader::HandshakeResponse { .. }
                    ) {
                        let now = clock.now();
                        if now.duration_since(secret_rotated) >= COOKIE_SECRET_ROTATION {
                            guard.rotate_secret(rand::random());
                            secret_rotated = now;
                        }
                        let force = under_load.load(Ordering::Relaxed);
                        match guard.check(now, segment, meta.addr, rand::random(), force) {
                            HandshakeDecision::Process => {}
                            HandshakeDecision::Drop => {
                                debug!("dropping handshake from {} (mac1)", meta.addr);
                                continue;
                            }
                            HandshakeDecision::Cookie(reply) => {
                                let _ = socket.send(meta.addr, &reply).await;
                                continue;
                            }
                        }
                    }
                    match header {
                        MessageHeader::HandshakeInit => {
                            match Handshake::receive(&our_private, segment) {
                                Ok(handshake) => {
                                    let _ = router.recv_handshake_init(meta.addr, handshake);
                                }
                                Err(e) => {
                                    debug!(
                                        "dropping invalid handshake init from {}: {:?}",
                                        meta.addr, e
                                    );
                                }
                            }
                        }
                        MessageHeader::HandshakeResponse { receiver } => {
                            let _ =
                                router.recv_handshake_resp(meta.addr, receiver, segment.to_vec());
                        }
                        MessageHeader::Data { receiver } => {
                            let _ = router.recv_data(meta.addr, receiver, segment.to_vec());
                        }
                        MessageHeader::CookieReply { receiver } => {
                            let _ = router.recv_cookie_reply(receiver, segment.to_vec());
                        }
                    };
                }
            }
        }
    }

    fn register_peer(
        &self,
        public_key: &PublicKey,
        config: &PeerConfig,
    ) -> Result<Peer, RegisterError> {
        let (actions, status) = self
            .router
            .register_peer(public_key.clone())
            .ok_or(RegisterError::AlreadyRegistered)?;
        Ok(actor::spawn(
            self.our_key.clone(),
            public_key.clone(),
            config,
            Arc::downgrade(&self.router),
            self.socket.clone(),
            status,
            actions,
        ))
    }

    /// Registers a peer and returns its handle, initiating a handshake if the
    /// config carries an endpoint. Errors if the peer is already registered.
    pub async fn add_peer(
        &self,
        public_key: &PublicKey,
        config: PeerConfig,
    ) -> Result<Peer, RegisterError> {
        let peer = self.register_peer(public_key, &config)?;
        if let Some(endpoint) = config.endpoint {
            let _ = self.router.connect(peer.public_key(), endpoint).await;
        }
        Ok(peer)
    }

    /// Replaces a registered peer's pre-shared key and persistent keepalive
    /// without unregistering it or discarding protocol state. A configured
    /// endpoint also replaces the current endpoint; `None` leaves it alone.
    /// `None` clears the pre-shared key or disables persistent keepalive.
    pub async fn set_peer(
        &self,
        public_key: &PublicKey,
        config: PeerConfig,
    ) -> Result<(), SendError> {
        self.router.set_config(public_key, config).await
    }

    /// This tunnel's public key.
    pub fn public_key(&self) -> PublicKey {
        self.our_key.public_key()
    }

    /// The local UDP address the tunnel is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Status snapshots for every registered peer.
    pub fn peers(&self) -> Vec<PeerStatus> {
        self.router.peer_statuses()
    }

    /// Status snapshot for one peer, or `None` if it isn't registered.
    pub fn peer(&self, peer: &PublicKey) -> Option<PeerStatus> {
        self.router.peer_status(peer)
    }

    /// Binds the UDP socket and starts the tunnel's receive loop.
    pub async fn new(addr: SocketAddr, our_key: PrivateKey) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self::start(socket, our_key))
    }

    /// Starts the tunnel's receive loop using an already-bound UDP socket.
    ///
    /// Takes ownership of the socket. This lets callers apply platform-specific
    /// configuration, such as protecting an Android VPN socket, before any
    /// tunnel traffic is sent.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::net::UdpSocket;
    /// use tunstile_tunnel::{PrivateKey, Tunnel};
    ///
    /// # async fn start() -> Result<(), Box<dyn std::error::Error>> {
    /// let socket = UdpSocket::bind("0.0.0.0:0")?;
    /// // Apply platform-specific socket configuration here.
    /// let _tunnel = Tunnel::from_socket(socket, PrivateKey::random()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_socket(socket: std::net::UdpSocket, our_key: PrivateKey) -> io::Result<Self> {
        let socket = UdpSocket::from_std(socket)?;
        Ok(Self::start(socket, our_key))
    }

    fn start(socket: UdpSocket, our_key: PrivateKey) -> Self {
        let socket = Arc::new(socket);
        let router = Arc::new(RoutingTable::new());
        let under_load = Arc::new(AtomicBool::new(false));
        let our_key = Arc::new(our_key);
        let read_task = spawn(Self::read_loop(
            our_key.clone(),
            socket.clone(),
            router.clone(),
            under_load.clone(),
        ));
        Self {
            our_key,
            socket,
            router,
            #[cfg(test)]
            under_load,
            read_task,
        }
    }

    #[cfg(test)]
    fn force_under_load(&self) {
        self.under_load.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use tunstile_protocol::{
        handshake::{INIT_MSG_LENGTH, RESP_MSG_LENGTH},
        transport::Transport,
    };

    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[tokio::test]
    async fn starts_with_existing_socket() {
        let socket = std::net::UdpSocket::bind(loopback()).unwrap();
        let local_addr = socket.local_addr().unwrap();
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        let tunnel = Tunnel::from_socket(socket, private_key).await.unwrap();

        assert_eq!(tunnel.local_addr().unwrap(), local_addr);
        assert_eq!(tunnel.public_key(), public_key);
    }

    // The responder is forced under load, so the initiator's first handshake is
    // answered with a cookie challenge; it must decrypt the cookie, retransmit
    // with a valid mac2, and complete — exercising both cookie directions.
    #[tokio::test(flavor = "multi_thread")]
    async fn cookie_under_load() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();
        tunnel_b.force_under_load();

        let mut peer_a = tunnel_b
            .add_peer(&pk_a, PeerConfig::default())
            .await
            .unwrap();
        let peer_b = tunnel_a
            .add_peer(
                &pk_b,
                PeerConfig {
                    endpoint: Some(addr_b),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(7), peer_b.ready())
            .await
            .expect("handshake did not complete through the cookie challenge")
            .unwrap();

        let payload = b"through the cookie".to_vec();
        peer_b.send(payload.clone()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), peer_a.recv())
            .await
            .expect("payload not delivered")
            .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tunnel_e2e() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        // b is the responder; a initiates the handshake.
        let mut peer_a = tunnel_b
            .add_peer(&pk_a, PeerConfig::default())
            .await
            .unwrap();
        let mut peer_b = tunnel_a
            .add_peer(
                &pk_b,
                PeerConfig {
                    endpoint: Some(addr_b),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        peer_b.ready().await.unwrap();
        peer_a.ready().await.unwrap();

        // the initiator confirms the session with a keepalive
        let keepalive_len = Transport::packet_len(0) as u64;
        let stat = peer_b.status();
        assert_eq!(stat.tx_bytes, INIT_MSG_LENGTH as u64 + keepalive_len);
        assert_eq!(stat.rx_bytes, RESP_MSG_LENGTH as u64);
        let a_rx = stat.rx_bytes;
        let a_tx = stat.tx_bytes;

        let stat = peer_a.status();
        assert_eq!(stat.tx_bytes, RESP_MSG_LENGTH as u64);
        assert_eq!(stat.rx_bytes, INIT_MSG_LENGTH as u64 + keepalive_len);
        let b_rx = stat.rx_bytes;
        let b_tx = stat.tx_bytes;

        let payload_a = b"hello from a".to_vec();
        let payload_a_len = Transport::packet_len(payload_a.len()) as u64;
        peer_b.send(payload_a.clone()).await.unwrap();
        let data = peer_a.recv().await;
        assert_eq!(data.unwrap(), payload_a);

        let stat = tunnel_b.peer(&pk_a).unwrap();
        let b_rx = b_rx + payload_a_len;
        assert_eq!(stat.tx_bytes, b_tx);
        assert_eq!(stat.rx_bytes, b_rx);

        let stat = tunnel_a.peer(&pk_b).unwrap();
        let a_tx = a_tx + payload_a_len;
        assert_eq!(stat.tx_bytes, a_tx);
        assert_eq!(stat.rx_bytes, a_rx);

        let payload_b = b"hello from b".to_vec();
        let payload_b_len = Transport::packet_len(payload_a.len()) as u64;
        peer_a.send(payload_b.clone()).await.unwrap();
        let data = peer_b.recv().await;
        assert_eq!(data.unwrap(), payload_b);

        let stat = tunnel_a.peer(&pk_b).unwrap();
        assert_eq!(stat.tx_bytes, a_tx);
        assert_eq!(stat.rx_bytes, a_rx + payload_b_len);

        let stat = tunnel_b.peer(&pk_a).unwrap();
        assert_eq!(stat.tx_bytes, b_tx + payload_b_len);
        assert_eq!(stat.rx_bytes, b_rx);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn staged_send() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let mut peer_a = tunnel_b
            .add_peer(&pk_a, PeerConfig::default())
            .await
            .unwrap();
        let peer_b = tunnel_a
            .add_peer(
                &pk_b,
                PeerConfig {
                    endpoint: Some(addr_b),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        // no readiness wait: the payload stages until the handshake completes
        let payload = b"staged before handshake".to_vec();
        peer_b.send(payload.clone()).await.unwrap();

        let data = tokio::time::timeout(Duration::from_secs(5), peer_a.recv())
            .await
            .expect("staged payload not delivered")
            .unwrap();
        assert_eq!(data, payload);
    }

    // a send to a peer with no known endpoint stays staged (no handshake
    // possible) until the peer connects to us.
    #[tokio::test(flavor = "multi_thread")]
    async fn send_before_endpoint_known() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let peer_a = tunnel_b
            .add_peer(&pk_a, PeerConfig::default())
            .await
            .unwrap();
        let payload = b"staged before endpoint".to_vec();
        peer_a.send(payload.clone()).await.unwrap();
        assert!(peer_a.status().last_send.is_none());

        let mut peer_b = tunnel_a
            .add_peer(
                &pk_b,
                PeerConfig {
                    endpoint: Some(addr_b),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let data = tokio::time::timeout(Duration::from_secs(5), peer_b.recv())
            .await
            .expect("staged payload not delivered")
            .unwrap();
        assert_eq!(data, payload);
    }

    // the peer's inbound queue only closes once its actor has shut down,
    // which requires the tunnel drop to release the routing table
    #[tokio::test(flavor = "multi_thread")]
    async fn drop_terminates_actors() {
        let sk_a = PrivateKey::random();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let mut peer_b = tunnel_a
            .add_peer(&pk_b, PeerConfig::default())
            .await
            .unwrap();
        drop(tunnel_a);

        let closed = tokio::time::timeout(Duration::from_secs(2), peer_b.recv())
            .await
            .expect("peer actor leaked after tunnel drop");
        assert!(closed.is_none());
        assert_eq!(
            peer_b.send(b"closed".to_vec()).await,
            Err(SendError::TunnelClosed)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_registration() {
        let sk_a = PrivateKey::random();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let peer_b = tunnel_a
            .add_peer(&pk_b, PeerConfig::default())
            .await
            .unwrap();
        let sender_b = peer_b.sender();
        assert_eq!(
            tunnel_a.add_peer(&pk_b, PeerConfig::default()).await.err(),
            Some(RegisterError::AlreadyRegistered)
        );

        // dropping the handle unregisters the peer and frees the key
        drop(peer_b);
        assert!(tunnel_a.peer(&pk_b).is_none());
        assert_eq!(sender_b.try_send(Vec::new()), Err(SendError::PeerRemoved));
        assert_eq!(sender_b.send(Vec::new()).await, Err(SendError::PeerRemoved));
        let _peer_b = tunnel_a
            .add_peer(&pk_b, PeerConfig::default())
            .await
            .unwrap();
        assert!(tunnel_a.peer(&pk_b).is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preshared_key() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();
        let psk = PresharedKey::from([7u8; 32]);

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let mut peer_a = tunnel_b
            .add_peer(&pk_a, PeerConfig::default())
            .await
            .unwrap();
        let peer_b = tunnel_a
            .add_peer(
                &pk_b,
                PeerConfig {
                    endpoint: Some(addr_b),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), peer_b.ready())
            .await
            .expect("handshake did not complete")
            .unwrap();
        let rx_before_update = peer_b.status().rx_bytes;

        tunnel_b
            .set_peer(
                &pk_a,
                PeerConfig {
                    preshared_key: Some(psk.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        tunnel_a
            .set_peer(
                &pk_b,
                PeerConfig {
                    preshared_key: Some(psk),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        // Updating the pre-shared key leaves the established session usable.
        let payload = b"psk update".to_vec();
        peer_b.send(payload.clone()).await.unwrap();
        let data = tokio::time::timeout(Duration::from_secs(5), peer_a.recv())
            .await
            .expect("payload not delivered")
            .unwrap();
        assert_eq!(data, payload);

        // A later handshake uses the updated key on both sides.
        peer_b.connect(addr_b).await.unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            while peer_b.status().rx_bytes < rx_before_update + RESP_MSG_LENGTH as u64 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("replacement handshake did not complete");

        let payload = b"after psk update".to_vec();
        peer_b.send(payload.clone()).await.unwrap();
        let data = tokio::time::timeout(Duration::from_secs(5), peer_a.recv())
            .await
            .expect("payload not delivered after replacement handshake")
            .unwrap();
        assert_eq!(data, payload);
    }

    // a mismatched preshared key must not complete a handshake, and the
    // invalid response must not trigger an immediate re-initiation storm
    #[tokio::test(flavor = "multi_thread")]
    async fn preshared_key_mismatch() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let _peer_a = tunnel_b
            .add_peer(
                &pk_a,
                PeerConfig {
                    preshared_key: Some([1u8; 32].into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let peer_b = tunnel_a
            .add_peer(
                &pk_b,
                PeerConfig {
                    endpoint: Some(addr_b),
                    preshared_key: Some([2u8; 32].into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_secs(1), peer_b.ready())
                .await
                .is_err()
        );
        // one init sent; the invalid response was dropped without re-initiating
        assert_eq!(peer_b.status().tx_bytes, INIT_MSG_LENGTH as u64);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn persistent_keepalive() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let peer_a = tunnel_b
            .add_peer(&pk_a, PeerConfig::default())
            .await
            .unwrap();
        let peer_b = tunnel_a
            .add_peer(
                &pk_b,
                PeerConfig {
                    endpoint: Some(addr_b),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        peer_b.ready().await.unwrap();

        tunnel_a
            .set_peer(
                &pk_b,
                PeerConfig {
                    persistent_keepalive: Some(Duration::from_millis(100)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let sent = peer_b.status().tx_bytes;
        tokio::time::sleep(Duration::from_secs(1)).await;

        let keepalive_len = Transport::packet_len(0) as u64;
        let sent = peer_b.status().tx_bytes - sent;
        assert!(
            sent >= 2 * keepalive_len,
            "expected at least 2 keepalives, sent {sent} bytes"
        );
        assert!(peer_a.status().rx_bytes >= INIT_MSG_LENGTH as u64 + 2 * keepalive_len);
    }
}
