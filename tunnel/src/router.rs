//! Maps peer public keys and receiver indices to peer actors.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use tokio::sync::mpsc;
use tunstile_protocol::{
    PublicKey,
    handshake::{Handshake, InitReceived},
};

use crate::{PeerStatus, SendError, actor::PeerAction};

const PEER_ACTION_QUEUE_CAPACITY: usize = 1024;

/// An index-routing update for the read loop's [`IndexRouter`].
pub(crate) enum Control {
    /// Route `index` to the registered peer's actor.
    Bind(PublicKey, u32),
    /// Stop routing `index`.
    Retire(u32),
    /// Drop every index routed to this removed peer's actor.
    Purge(mpsc::Sender<PeerAction>),
}

pub(crate) struct PeerEntry {
    pub(crate) actions: mpsc::Sender<PeerAction>,
    pub(crate) status: Arc<RwLock<PeerStatus>>,
}

/// The peer registry, shared between the tunnel handle and the read loop.
pub(crate) struct RoutingTable {
    peers: RwLock<HashMap<PublicKey, Arc<PeerEntry>>>,
    control: mpsc::UnboundedSender<Control>,
}

impl RoutingTable {
    pub(crate) fn new(control: mpsc::UnboundedSender<Control>) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            control,
        }
    }

    pub(crate) fn register_peer(
        &self,
        peer_key: PublicKey,
    ) -> Option<(mpsc::Receiver<PeerAction>, Arc<PeerEntry>)> {
        let mut peers = self.peers.write().unwrap();
        if peers.contains_key(&peer_key) {
            return None;
        }
        let (tx, rx) = mpsc::channel(PEER_ACTION_QUEUE_CAPACITY);
        let status = Arc::new(RwLock::new(PeerStatus {
            public_key: peer_key.clone(),
            endpoint: None,
            tx_bytes: 0,
            rx_bytes: 0,
            last_send: None,
            last_recv: None,
            last_successful_handshake: None,
        }));
        let entry = Arc::new(PeerEntry {
            actions: tx,
            status,
        });
        peers.insert(peer_key, entry.clone());
        Some((rx, entry))
    }

    pub(crate) fn remove_peer(&self, peer_key: &PublicKey) {
        let Some(entry) = self.peers.write().unwrap().remove(peer_key) else {
            return;
        };
        let _ = self.control.send(Control::Purge(entry.actions.clone()));
    }

    pub(crate) fn entry(&self, public_key: &PublicKey) -> Option<Arc<PeerEntry>> {
        self.peers.read().unwrap().get(public_key).cloned()
    }

    pub(crate) fn peer_status(&self, public_key: &PublicKey) -> Option<PeerStatus> {
        self.entry(public_key)
            .map(|entry| entry.status.read().unwrap().clone())
    }

    pub(crate) fn peer_statuses(&self) -> Vec<PeerStatus> {
        self.peers
            .read()
            .unwrap()
            .values()
            .map(|entry| entry.status.read().unwrap().clone())
            .collect()
    }

    pub(crate) async fn set_peer(
        &self,
        public_key: &PublicKey,
        update: crate::PeerUpdate,
    ) -> Result<(), SendError> {
        let entry = self.entry(public_key).ok_or(SendError::PeerRemoved)?;
        entry
            .actions
            .send(PeerAction::Update(update))
            .await
            .map_err(|_| SendError::PeerRemoved)
    }

    pub(crate) fn recv_handshake_init(
        &self,
        endpoint: SocketAddr,
        handshake: Handshake<InitReceived>,
    ) {
        if let Some(entry) = self.entry(handshake.peer_key()) {
            let _ = entry
                .actions
                .try_send(PeerAction::RecvHandshakeInit(handshake, endpoint));
        }
    }
}

/// Receiver-index routing, owned exclusively by the read loop and updated
/// through [`Control`] messages.
pub(crate) struct IndexRouter {
    indices: HashMap<u32, mpsc::Sender<PeerAction>>,
}

impl IndexRouter {
    pub(crate) fn new() -> Self {
        Self {
            indices: HashMap::new(),
        }
    }

    pub(crate) fn apply(&mut self, control: Control, peers: &RoutingTable) {
        match control {
            Control::Bind(peer_key, index) => {
                // a bind racing a removal must not route to the dead actor;
                // the registry entry is removed before the purge is sent, so
                // a late bind finds no entry here
                let Some(entry) = peers.entry(&peer_key) else {
                    return;
                };
                self.indices.insert(index, entry.actions.clone());
            }
            Control::Retire(index) => {
                self.indices.remove(&index);
            }
            Control::Purge(actions) => {
                self.indices.retain(|_, s| !s.same_channel(&actions));
            }
        }
    }

    fn try_send_to_index(&self, index: u32, action: PeerAction) {
        if let Some(sender) = self.indices.get(&index) {
            let _ = sender.try_send(action);
        }
    }

    pub(crate) fn recv_data(&self, endpoint: SocketAddr, peer_index: u32, packet: Vec<u8>) {
        self.try_send_to_index(
            peer_index,
            PeerAction::RecvData(packet, peer_index, endpoint),
        );
    }

    pub(crate) fn recv_handshake_resp(
        &self,
        endpoint: SocketAddr,
        peer_index: u32,
        packet: Vec<u8>,
    ) {
        self.try_send_to_index(peer_index, PeerAction::RecvHandshakeResp(packet, endpoint));
    }

    pub(crate) fn recv_cookie_reply(&self, peer_index: u32, packet: Vec<u8>) {
        self.try_send_to_index(peer_index, PeerAction::RecvCookieReply(packet));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunstile_protocol::PrivateKey;

    fn table() -> (RoutingTable, mpsc::UnboundedReceiver<Control>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (RoutingTable::new(tx), rx)
    }

    #[test]
    fn full_peer_queue_does_not_accept_network_input() {
        let (router, _control) = table();
        let public_key = PrivateKey::random().public_key();
        let (mut actions, entry) = router.register_peer(public_key.clone()).unwrap();
        let mut indices = IndexRouter::new();
        indices.apply(Control::Bind(public_key, 7), &router);

        for _ in 0..PEER_ACTION_QUEUE_CAPACITY {
            entry
                .actions
                .try_send(PeerAction::SendData(Vec::new()))
                .unwrap();
        }

        assert!(
            entry
                .actions
                .try_send(PeerAction::SendData(Vec::new()))
                .is_err()
        );
        indices.recv_data("127.0.0.1:1".parse().unwrap(), 7, Vec::new());

        let mut queued = 0;
        while let Ok(action) = actions.try_recv() {
            assert!(matches!(action, PeerAction::SendData(_)));
            queued += 1;
        }
        assert_eq!(queued, PEER_ACTION_QUEUE_CAPACITY);
    }

    // a bind that loses the race with a removal must not plant a route to
    // the dead actor
    #[test]
    fn bind_after_removal_is_ignored() {
        let (router, _control) = table();
        let public_key = PrivateKey::random().public_key();
        let (mut actions, _entry) = router.register_peer(public_key.clone()).unwrap();
        router.remove_peer(&public_key);

        let mut indices = IndexRouter::new();
        indices.apply(Control::Bind(public_key, 7), &router);
        indices.recv_data("127.0.0.1:1".parse().unwrap(), 7, b"data".to_vec());
        assert!(actions.try_recv().is_err());
    }
}
