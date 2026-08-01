//! Maps peer public keys and receiver indices to peer actors.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use tokio::sync::mpsc::{self, Sender, error::TrySendError};
use tunstile_protocol::{
    PublicKey,
    handshake::{Handshake, InitReceived},
};

use crate::{PeerStatus, SendError, actor::PeerAction};

const PEER_ACTION_QUEUE_CAPACITY: usize = 1024;

struct PeerEntry {
    actions: mpsc::Sender<PeerAction>,
    status: Arc<RwLock<PeerStatus>>,
}

pub(crate) struct RoutingTable {
    peer_indices: RwLock<HashMap<u32, mpsc::Sender<PeerAction>>>,
    peers: RwLock<HashMap<PublicKey, PeerEntry>>,
}

impl RoutingTable {
    pub(crate) fn new() -> Self {
        Self {
            peer_indices: RwLock::new(HashMap::new()),
            peers: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) fn bind_index(&self, peer_key: &PublicKey, index: u32) {
        let Some(sender) = self.peer_key_sender(peer_key) else {
            return;
        };
        self.peer_indices.write().unwrap().insert(index, sender);
    }

    pub(crate) fn retire_index(&self, index: u32) {
        self.peer_indices.write().unwrap().remove(&index);
    }

    pub(crate) fn remove_peer(&self, peer_key: &PublicKey) {
        let Some(entry) = self.peers.write().unwrap().remove(peer_key) else {
            return;
        };
        self.peer_indices
            .write()
            .unwrap()
            .retain(|_, s| !s.same_channel(&entry.actions));
    }

    pub(crate) fn register_peer(
        &self,
        peer_key: PublicKey,
    ) -> Option<(mpsc::Receiver<PeerAction>, Arc<RwLock<PeerStatus>>)> {
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
        peers.insert(
            peer_key,
            PeerEntry {
                actions: tx,
                status: status.clone(),
            },
        );
        Some((rx, status))
    }

    fn peer_key_sender(&self, public_key: &PublicKey) -> Option<Sender<PeerAction>> {
        self.peers
            .read()
            .unwrap()
            .get(public_key)
            .map(|entry| entry.actions.clone())
    }

    pub(crate) fn peer_status(&self, public_key: &PublicKey) -> Option<PeerStatus> {
        self.peers
            .read()
            .unwrap()
            .get(public_key)
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

    fn peer_index_sender(&self, index: u32) -> Option<Sender<PeerAction>> {
        self.peer_indices.read().unwrap().get(&index).cloned()
    }

    async fn send_action(
        &self,
        public_key: &PublicKey,
        action: PeerAction,
    ) -> Result<(), SendError> {
        let sender = self
            .peer_key_sender(public_key)
            .ok_or(SendError::PeerRemoved)?;
        sender
            .send(action)
            .await
            .map_err(|_| SendError::PeerRemoved)
    }

    fn try_send_to_index(&self, index: u32, action: PeerAction) {
        if let Some(sender) = self.peer_index_sender(index) {
            let _ = sender.try_send(action);
        }
    }

    pub(crate) async fn connect(
        &self,
        public_key: &PublicKey,
        endpoint: SocketAddr,
    ) -> Result<(), SendError> {
        self.send_action(public_key, PeerAction::Connect(endpoint))
            .await
    }

    pub(crate) async fn set_config(
        &self,
        public_key: &PublicKey,
        config: crate::PeerConfig,
    ) -> Result<(), SendError> {
        self.send_action(public_key, PeerAction::SetConfig(config))
            .await
    }

    pub(crate) async fn send_data(
        &self,
        public_key: &PublicKey,
        packet: Vec<u8>,
    ) -> Result<(), SendError> {
        self.send_action(public_key, PeerAction::SendData(packet))
            .await
    }

    pub(crate) fn try_send_data(
        &self,
        public_key: &PublicKey,
        packet: Vec<u8>,
    ) -> Result<(), SendError> {
        let sender = self
            .peer_key_sender(public_key)
            .ok_or(SendError::PeerRemoved)?;
        sender
            .try_send(PeerAction::SendData(packet))
            .map_err(|error| match error {
                TrySendError::Full(_) => SendError::Full,
                TrySendError::Closed(_) => SendError::PeerRemoved,
            })
    }

    pub(crate) fn recv_handshake_init(
        &self,
        endpoint: SocketAddr,
        handshake: Handshake<InitReceived>,
    ) {
        if let Some(sender) = self.peer_key_sender(handshake.peer_key()) {
            let _ = sender.try_send(PeerAction::RecvHandshakeInit(handshake, endpoint));
        }
    }

    pub(crate) fn recv_handshake_resp(
        &self,
        endpoint: SocketAddr,
        peer_index: u32,
        packet: Vec<u8>,
    ) {
        self.try_send_to_index(peer_index, PeerAction::RecvHandshakeResp(packet, endpoint));
    }

    pub(crate) fn recv_data(&self, endpoint: SocketAddr, peer_index: u32, packet: Vec<u8>) {
        self.try_send_to_index(
            peer_index,
            PeerAction::RecvData(packet, peer_index, endpoint),
        );
    }

    pub(crate) fn recv_cookie_reply(&self, peer_index: u32, packet: Vec<u8>) {
        self.try_send_to_index(peer_index, PeerAction::RecvCookieReply(packet));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunstile_protocol::PrivateKey;

    #[test]
    fn full_peer_queue_does_not_accept_network_input() {
        let router = RoutingTable::new();
        let public_key = PrivateKey::random().public_key();
        let (mut actions, _) = router.register_peer(public_key.clone()).unwrap();
        router.bind_index(&public_key, 7);

        for _ in 0..PEER_ACTION_QUEUE_CAPACITY {
            assert_eq!(router.try_send_data(&public_key, Vec::new()), Ok(()));
        }

        assert_eq!(
            router.try_send_data(&public_key, Vec::new()),
            Err(SendError::Full)
        );
        router.recv_data("127.0.0.1:1".parse().unwrap(), 7, Vec::new());

        let mut queued = 0;
        while let Ok(action) = actions.try_recv() {
            assert!(matches!(action, PeerAction::SendData(_)));
            queued += 1;
        }
        assert_eq!(queued, PEER_ACTION_QUEUE_CAPACITY);
    }
}
