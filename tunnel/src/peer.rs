//! Public peer handles: the owning [`Peer`] and the cloneable [`PeerSender`].

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock, Weak},
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::sync::{mpsc, watch};
use tunstile_protocol::PublicKey;

use crate::{PeerStatus, SendError, router::RoutingTable};

/// A handle to a registered peer: the owned receive half of its inbound
/// queue plus its send and status operations. The handle is the
/// registration — dropping it removes the peer from the tunnel.
#[must_use = "dropping the Peer unregisters it from the tunnel"]
pub struct Peer {
    public_key: PublicKey,
    router: Weak<RoutingTable>,
    status: Arc<RwLock<PeerStatus>>,
    session_rx: watch::Receiver<bool>,
    data_rx: mpsc::Receiver<Bytes>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(router) = self.router.upgrade() {
            router.remove_peer(&self.public_key);
        }
    }
}

impl Peer {
    pub(crate) fn new(
        public_key: PublicKey,
        router: Weak<RoutingTable>,
        status: Arc<RwLock<PeerStatus>>,
        session_rx: watch::Receiver<bool>,
        data_rx: mpsc::Receiver<Bytes>,
    ) -> Self {
        Self {
            public_key,
            router,
            status,
            session_rx,
            data_rx,
        }
    }

    /// This peer's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Current status snapshot for this peer.
    pub fn status(&self) -> PeerStatus {
        self.status.read().unwrap().clone()
    }

    /// Receives the next decrypted payload from this peer. Returns `None`
    /// once the peer is removed or the tunnel is dropped.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.data_rx.recv().await
    }

    /// Sends a payload to this peer, staging it if no session is established yet.
    pub async fn send(&self, payload: impl Into<Bytes>) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::Closed)?;
        router.send_data(&self.public_key, payload.into()).await
    }

    /// Updates the peer's endpoint and initiates a handshake if none is in
    /// flight. Use when the peer's address changes, e.g. after a DNS re-resolve.
    pub async fn connect(&self, endpoint: SocketAddr) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::Closed)?;
        router.connect(&self.public_key, endpoint).await
    }

    /// Resolves once a session is established with the peer. Errors if the
    /// tunnel is dropped first.
    pub async fn ready(&self) -> Result<(), SendError> {
        self.session_rx
            .clone()
            .wait_for(|ready| *ready)
            .await
            .map(|_| ())
            .map_err(|_| SendError::Closed)
    }

    /// Returns a cloneable send handle. Unlike the `Peer`, it does not own the
    /// registration: dropping every sender does not remove the peer.
    pub fn sender(&self) -> PeerSender {
        PeerSender {
            public_key: self.public_key.clone(),
            router: self.router.clone(),
        }
    }
}

impl futures_core::Stream for Peer {
    type Item = Bytes;

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

    /// Sends a payload to the peer, staging it if no session is established yet.
    pub async fn send(&self, payload: impl Into<Bytes>) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::Closed)?;
        router.send_data(&self.public_key, payload.into()).await
    }

    /// Updates the peer's endpoint and initiates a handshake if none is pending.
    pub async fn connect(&self, endpoint: SocketAddr) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::Closed)?;
        router.connect(&self.public_key, endpoint).await
    }

    /// Current status snapshot, or `None` if the peer is no longer registered.
    pub fn status(&self) -> Option<PeerStatus> {
        self.router.upgrade()?.peer_status(&self.public_key)
    }
}
