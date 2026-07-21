//! Maps peer public keys and receiver indices to peer actors.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use bytes::Bytes;
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

    pub(crate) fn bind_index(&self, peer_key: &PublicKey, index: u32) -> bool {
        let Some(sender) = self.peer_key_sender(peer_key) else {
            return false;
        };
        self.peer_indices.write().unwrap().insert(index, sender);
        true
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

    pub(crate) async fn connect(
        &self,
        public_key: &PublicKey,
        endpoint: SocketAddr,
    ) -> Result<(), SendError> {
        let sender = self
            .peer_key_sender(public_key)
            .ok_or(SendError::PeerRemoved)?;
        sender
            .send(PeerAction::Connect(endpoint))
            .await
            .map_err(|_| SendError::PeerRemoved)
    }

    pub(crate) async fn set_config(
        &self,
        public_key: &PublicKey,
        config: crate::PeerConfig,
    ) -> Result<(), SendError> {
        let sender = self
            .peer_key_sender(public_key)
            .ok_or(SendError::PeerRemoved)?;
        sender
            .send(PeerAction::SetConfig(config))
            .await
            .map_err(|_| SendError::PeerRemoved)
    }

    pub(crate) async fn send_data(
        &self,
        public_key: &PublicKey,
        packet: Bytes,
    ) -> Result<(), SendError> {
        let sender = self
            .peer_key_sender(public_key)
            .ok_or(SendError::PeerRemoved)?;
        sender
            .send(PeerAction::SendData(packet))
            .await
            .map_err(|_| SendError::PeerRemoved)
    }

    pub(crate) fn try_send_data(
        &self,
        public_key: &PublicKey,
        packet: Bytes,
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
    ) -> bool {
        if let Some(sender) = self.peer_key_sender(handshake.peer_key()) {
            return sender
                .try_send(PeerAction::RecvHandshakeInit(handshake, endpoint))
                .is_ok();
        }
        false
    }

    pub(crate) fn recv_handshake_resp(
        &self,
        endpoint: SocketAddr,
        peer_index: u32,
        packet: Vec<u8>,
    ) -> bool {
        if let Some(sender) = self.peer_index_sender(peer_index) {
            return sender
                .try_send(PeerAction::RecvHandshakeResp(packet, endpoint))
                .is_ok();
        }
        false
    }

    pub(crate) fn recv_data(&self, endpoint: SocketAddr, peer_index: u32, packet: Vec<u8>) -> bool {
        if let Some(sender) = self.peer_index_sender(peer_index) {
            return sender
                .try_send(PeerAction::RecvData(packet, peer_index, endpoint))
                .is_ok();
        }
        false
    }

    pub(crate) fn recv_cookie_reply(&self, peer_index: u32, packet: Vec<u8>) -> bool {
        if let Some(sender) = self.peer_index_sender(peer_index) {
            return sender.try_send(PeerAction::RecvCookieReply(packet)).is_ok();
        }
        false
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
        let (_actions, _) = router.register_peer(public_key.clone()).unwrap();
        assert!(router.bind_index(&public_key, 7));

        for _ in 0..PEER_ACTION_QUEUE_CAPACITY {
            assert_eq!(router.try_send_data(&public_key, Bytes::new()), Ok(()));
        }

        assert_eq!(
            router.try_send_data(&public_key, Bytes::new()),
            Err(SendError::Full)
        );
        assert!(!router.recv_data("127.0.0.1:1".parse().unwrap(), 7, Vec::new()));
    }
}
