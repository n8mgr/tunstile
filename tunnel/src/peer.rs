//! Public peer handles: the owning [`Peer`] and the cloneable [`PeerSender`].

use std::{
    net::SocketAddr,
    sync::{Arc, Weak},
};

use tokio::sync::{mpsc::error::TrySendError, watch};
use tunstile_protocol::PublicKey;

use crate::{
    PeerStatus, SendError,
    actor::PeerAction,
    router::{PeerEntry, RoutingTable},
};

/// A handle to a registered peer: its send, connect, and status operations.
/// Decrypted payloads arrive through [`Tunnel::recv`](crate::Tunnel::recv).
/// The handle is the registration — dropping it removes the peer from the
/// tunnel.
#[must_use = "dropping the Peer unregisters it from the tunnel"]
pub struct Peer {
    sender: PeerSender,
    session_rx: watch::Receiver<bool>,
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
        entry: Weak<PeerEntry>,
        session_rx: watch::Receiver<bool>,
    ) -> Self {
        Self {
            sender: PeerSender {
                public_key,
                router,
                entry,
            },
            session_rx,
        }
    }

    /// This peer's public key.
    pub fn public_key(&self) -> &PublicKey {
        self.sender.public_key()
    }

    /// Current status snapshot, or `None` once the tunnel is dropped.
    pub fn status(&self) -> Option<PeerStatus> {
        self.sender.status()
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

/// A cloneable handle for sending to a peer. Unlike [`Peer`] it does not own
/// the registration, so many callers can share the send path.
#[derive(Clone)]
pub struct PeerSender {
    public_key: PublicKey,
    router: Weak<RoutingTable>,
    entry: Weak<PeerEntry>,
}

impl PeerSender {
    fn entry(&self) -> Result<Arc<PeerEntry>, SendError> {
        match self.entry.upgrade() {
            Some(entry) => Ok(entry),
            None if self.router.upgrade().is_some() => Err(SendError::PeerRemoved),
            None => Err(SendError::TunnelClosed),
        }
    }

    /// The peer's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Sends a payload to the peer, waiting for queue capacity. Pre-session
    /// staging is bounded and may discard older payloads.
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        self.entry()?
            .actions
            .send(PeerAction::SendData(payload))
            .await
            .map_err(|_| SendError::PeerRemoved)
    }

    /// Sends a payload immediately, returning [`SendError::Full`] instead of
    /// waiting when this peer's queue has no capacity.
    pub fn try_send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        self.entry()?
            .actions
            .try_send(PeerAction::SendData(payload))
            .map_err(|error| match error {
                TrySendError::Full(_) => SendError::Full,
                TrySendError::Closed(_) => SendError::PeerRemoved,
            })
    }

    /// Updates the peer's endpoint and initiates a handshake if none is in
    /// flight.
    pub async fn connect(&self, endpoint: SocketAddr) -> Result<(), SendError> {
        self.entry()?
            .actions
            .send(PeerAction::Connect(endpoint))
            .await
            .map_err(|_| SendError::PeerRemoved)
    }

    /// Current status snapshot, or `None` if the peer is no longer registered.
    pub fn status(&self) -> Option<PeerStatus> {
        self.entry
            .upgrade()
            .map(|entry| entry.status.read().unwrap().clone())
    }
}
