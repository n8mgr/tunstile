//! Public peer handles: the owning [`Peer`] and the cloneable [`PeerSender`].

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock, Weak},
    task::{Context, Poll},
};

use tokio::sync::{mpsc, watch};
use tunstile_protocol::PublicKey;

use crate::{PeerStatus, SendError, router::RoutingTable};

/// A handle to a registered peer: the owned receive half of its inbound
/// queue plus its send and status operations. The handle is the
/// registration — dropping it removes the peer from the tunnel.
#[must_use = "dropping the Peer unregisters it from the tunnel"]
pub struct Peer {
    sender: PeerSender,
    status: Arc<RwLock<PeerStatus>>,
    session_rx: watch::Receiver<bool>,
    data_rx: mpsc::Receiver<Vec<u8>>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(router) = self.sender.router.upgrade() {
            router.remove_peer(self.sender.public_key());
        }
    }
}

impl Peer {
    pub(crate) fn new(
        public_key: PublicKey,
        router: Weak<RoutingTable>,
        status: Arc<RwLock<PeerStatus>>,
        session_rx: watch::Receiver<bool>,
        data_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            sender: PeerSender { public_key, router },
            status,
            session_rx,
            data_rx,
        }
    }

    /// This peer's public key.
    pub fn public_key(&self) -> &PublicKey {
        self.sender.public_key()
    }

    /// Current status snapshot for this peer.
    pub fn status(&self) -> PeerStatus {
        self.status.read().unwrap().clone()
    }

    /// Receives the next decrypted payload from this peer. Returns `None`
    /// once the peer is removed or the tunnel is dropped.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.data_rx.recv().await
    }

    /// Sends a payload to this peer, waiting for queue capacity. Pre-session
    /// staging is bounded and may discard older payloads.
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        self.sender.send(payload).await
    }

    /// Sends a payload immediately, returning [`SendError::Full`] instead of
    /// waiting when this peer's queue has no capacity.
    pub fn try_send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        self.sender.try_send(payload)
    }

    /// Updates the peer's endpoint and initiates a handshake if none is in
    /// flight. Use when the peer's address changes, e.g. after a DNS re-resolve.
    pub async fn connect(&self, endpoint: SocketAddr) -> Result<(), SendError> {
        self.sender.connect(endpoint).await
    }

    /// Resolves once a session is established with the peer. Errors if the
    /// tunnel is dropped first.
    pub async fn ready(&self) -> Result<(), SendError> {
        self.session_rx
            .clone()
            .wait_for(|ready| *ready)
            .await
            .map(|_| ())
            .map_err(|_| SendError::TunnelClosed)
    }

    /// Returns a cloneable send handle. Unlike the `Peer`, it does not own the
    /// registration: dropping every sender does not remove the peer.
    pub fn sender(&self) -> PeerSender {
        self.sender.clone()
    }
}

impl futures_core::Stream for Peer {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().data_rx.poll_recv(cx)
    }
}

/// A cloneable handle for sending to a peer, decoupled from its inbound
/// queue so many callers can share the send path.
#[derive(Clone)]
pub struct PeerSender {
    public_key: PublicKey,
    router: Weak<RoutingTable>,
}

impl PeerSender {
    /// The peer's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Sends a payload to the peer, waiting for queue capacity. Pre-session
    /// staging is bounded and may discard older payloads.
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::TunnelClosed)?;
        router.send_data(&self.public_key, payload).await
    }

    /// Sends a payload immediately, returning [`SendError::Full`] instead of
    /// waiting when this peer's queue has no capacity.
    pub fn try_send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::TunnelClosed)?;
        router.try_send_data(&self.public_key, payload)
    }

    /// Updates the peer's endpoint and initiates a handshake if none is in
    /// flight.
    pub async fn connect(&self, endpoint: SocketAddr) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::TunnelClosed)?;
        router.connect(&self.public_key, endpoint).await
    }

    /// Current status snapshot, or `None` if the peer is no longer registered.
    pub fn status(&self) -> Option<PeerStatus> {
        self.router.upgrade()?.peer_status(&self.public_key)
    }
}
