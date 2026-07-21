//! A packet-oriented WireGuard device with AllowedIPs routing and source
//! validation.
//!
//! # Example
//!
//! ```no_run
//! use std::{error::Error, net::SocketAddr};
//! use tunstile::{Device, PeerConfig, PrivateKey, PublicKey};
//!
//! async fn start(
//!     private_key: PrivateKey,
//!     peer_key: PublicKey,
//!     endpoint: SocketAddr,
//! ) -> Result<Device, Box<dyn Error>> {
//!     let device = Device::new("0.0.0.0:0".parse()?, private_key).await?;
//!     device
//!         .add_peer(
//!             &peer_key,
//!             PeerConfig {
//!                 endpoint: Some(endpoint),
//!                 allowed_ips: vec!["0.0.0.0/0".parse()?],
//!                 ..Default::default()
//!             },
//!         )
//!         .await?;
//!     Ok(device)
//! }
//! ```

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};

pub use bytes::Bytes;
use log::debug;
use thiserror::Error;
use tokio::{
    spawn,
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tunstile_tunnel::{Peer, PeerSender, Tunnel};

mod allowed_ips;
mod config;
pub use config::PeerConfig;
pub use ipnet::IpNet;
pub use tunstile_tunnel::{KeyParseError, PeerStatus, PrivateKey, PublicKey, SendError};

type AllowedIpTable = Arc<RwLock<allowed_ips::AllowedIps<PeerSender>>>;

const PACKET_QUEUE_CAPACITY: usize = 1024;

/// Error creating or operating a device.
#[derive(Debug, Error)]
pub enum DeviceError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("peer already registered")]
    DuplicatePeer,

    #[error("invalid IP packet")]
    InvalidPacket,

    #[error("no peer allows destination {0}")]
    NoPeer(IpAddr),

    #[error("peer {0} is not registered")]
    UnknownPeer(PublicKey),

    #[error(transparent)]
    Send(#[from] SendError),
}

/// A WireGuard device that routes plaintext IP packets to and from peers.
///
/// [`Device::send_packet`] accepts packets from a platform network interface.
/// [`Device::recv_packet`] returns authenticated packets to inject into that
/// interface. Peers remain registered until removed from the device.
pub struct Device {
    tunnel: Tunnel,
    peer_updates: Mutex<()>,
    peers: RwLock<HashMap<PublicKey, PeerEntry>>,
    allowed_ips: AllowedIpTable,
    inbound_tx: mpsc::Sender<Bytes>,
    inbound_rx: Mutex<mpsc::Receiver<Bytes>>,
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Ok(peers) = self.peers.get_mut() {
            for entry in peers.values() {
                entry.task.abort();
            }
        }
    }
}

impl Device {
    fn start(tunnel: Tunnel) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(PACKET_QUEUE_CAPACITY);
        Self {
            tunnel,
            peer_updates: Mutex::new(()),
            peers: RwLock::new(HashMap::new()),
            allowed_ips: Arc::new(RwLock::new(allowed_ips::AllowedIps::new())),
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
        }
    }

    /// Binds the UDP socket and creates a device with no peers.
    pub async fn new(
        listen_addr: SocketAddr,
        private_key: PrivateKey,
    ) -> Result<Self, DeviceError> {
        let tunnel = Tunnel::new(listen_addr, private_key).await?;
        Ok(Self::start(tunnel))
    }

    /// Creates a device using an already-bound UDP socket.
    pub async fn from_socket(
        socket: std::net::UdpSocket,
        private_key: PrivateKey,
    ) -> Result<Self, DeviceError> {
        let tunnel = Tunnel::from_socket(socket, private_key).await?;
        Ok(Self::start(tunnel))
    }

    /// This device's public key.
    pub fn public_key(&self) -> PublicKey {
        self.tunnel.public_key()
    }

    /// The local UDP address used for encrypted tunnel traffic.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tunnel.local_addr()
    }

    /// Status snapshots for every registered peer.
    pub fn peers(&self) -> Vec<PeerStatus> {
        self.tunnel.peers()
    }

    /// Status snapshot for one peer, or `None` if it isn't registered.
    pub fn peer(&self, public_key: &PublicKey) -> Option<PeerStatus> {
        self.tunnel.peer(public_key)
    }

    fn route_packet(&self, packet: &[u8]) -> Result<PeerSender, DeviceError> {
        let destination = packet_dst(packet).ok_or(DeviceError::InvalidPacket)?;
        self.allowed_ips
            .read()
            .unwrap()
            .longest_match(destination)
            .cloned()
            .ok_or(DeviceError::NoPeer(destination))
    }

    /// Routes an outbound IP packet to the peer with the most-specific
    /// matching AllowedIP, waiting for space in that peer's send queue.
    pub async fn send_packet(&self, packet: impl Into<Bytes>) -> Result<(), DeviceError> {
        let packet = packet.into();
        self.route_packet(&packet)?.send(packet).await?;
        Ok(())
    }

    /// Routes an outbound IP packet immediately, returning
    /// [`SendError::Full`] instead of waiting when the selected peer's send
    /// queue has no capacity.
    pub fn try_send_packet(&self, packet: impl Into<Bytes>) -> Result<(), DeviceError> {
        let packet = packet.into();
        self.route_packet(&packet)?.try_send(packet)?;
        Ok(())
    }

    /// Receives the next authenticated inbound IP packet.
    ///
    /// Only one receiver should call this method at a time.
    pub async fn recv_packet(&self) -> Option<Bytes> {
        self.inbound_rx.lock().await.recv().await
    }

    /// Registers a peer and its AllowedIPs.
    pub async fn add_peer(
        &self,
        public_key: &PublicKey,
        config: PeerConfig,
    ) -> Result<(), DeviceError> {
        let _update = self.peer_updates.lock().await;
        if self.peers.read().unwrap().contains_key(public_key) {
            return Err(DeviceError::DuplicatePeer);
        }
        let peer = self
            .tunnel
            .add_peer(public_key, config.to_tunnel())
            .await
            .map_err(|_| DeviceError::DuplicatePeer)?;
        let sender = peer.sender();
        {
            let mut allowed_ips = self.allowed_ips.write().unwrap();
            for net in &config.allowed_ips {
                allowed_ips.insert(*net, sender.clone());
            }
        }
        let task = spawn(inbound_loop(
            self.inbound_tx.clone(),
            self.allowed_ips.clone(),
            peer,
        ));
        let previous = self
            .peers
            .write()
            .unwrap()
            .insert(public_key.clone(), PeerEntry { sender, task });
        debug_assert!(previous.is_none());
        Ok(())
    }

    /// Replaces a registered peer's AllowedIPs, pre-shared key, and persistent
    /// keepalive without unregistering it or discarding protocol state. A
    /// configured endpoint also replaces the current endpoint; `None` leaves
    /// it alone. `None` clears the pre-shared key or disables persistent
    /// keepalive; an empty `allowed_ips` removes all of the peer's routes.
    pub async fn set_peer(
        &self,
        public_key: &PublicKey,
        config: PeerConfig,
    ) -> Result<(), DeviceError> {
        let _update = self.peer_updates.lock().await;
        if !self.peers.read().unwrap().contains_key(public_key) {
            return Err(DeviceError::UnknownPeer(public_key.clone()));
        }

        self.tunnel.set_peer(public_key, config.to_tunnel()).await?;

        let peers = self.peers.read().unwrap();
        let entry = peers
            .get(public_key)
            .ok_or_else(|| DeviceError::UnknownPeer(public_key.clone()))?;
        let mut allowed_ips = self.allowed_ips.write().unwrap();
        allowed_ips.retain(|owner| owner.public_key() != public_key);
        for net in config.allowed_ips {
            allowed_ips.insert(net, entry.sender.clone());
        }
        Ok(())
    }

    /// Updates a peer's endpoint and initiates a handshake if none is in
    /// flight.
    pub async fn connect_peer(
        &self,
        public_key: &PublicKey,
        endpoint: SocketAddr,
    ) -> Result<(), DeviceError> {
        let _update = self.peer_updates.lock().await;
        let sender = self
            .peers
            .read()
            .unwrap()
            .get(public_key)
            .map(|entry| entry.sender.clone())
            .ok_or_else(|| DeviceError::UnknownPeer(public_key.clone()))?;
        sender.connect(endpoint).await?;
        Ok(())
    }

    /// Unregisters a peer and removes its AllowedIPs.
    pub async fn remove_peer(&self, public_key: &PublicKey) -> bool {
        let _update = self.peer_updates.lock().await;
        let entry = self.peers.write().unwrap().remove(public_key);
        let Some(entry) = entry else {
            return false;
        };
        self.allowed_ips
            .write()
            .unwrap()
            .retain(|sender| sender.public_key() != public_key);
        entry.task.abort();
        let _ = entry.task.await;
        true
    }
}

struct PeerEntry {
    sender: PeerSender,
    task: JoinHandle<()>,
}

async fn inbound_loop(inbound: mpsc::Sender<Bytes>, allowed_ips: AllowedIpTable, mut peer: Peer) {
    while let Some(packet) = peer.recv().await {
        let Some(source) = packet_src(&packet) else {
            continue;
        };
        let valid_source = allowed_ips
            .read()
            .unwrap()
            .longest_match(source)
            .is_some_and(|sender| sender.public_key() == peer.public_key());
        if !valid_source {
            debug!("inbound packet from unexpected source {source}; dropping");
            continue;
        }
        if inbound.send(packet).await.is_err() {
            break;
        }
    }
}

fn packet_dst(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => Some(IpAddr::V6(v6(&packet[24..40]))),
        _ => None,
    }
}

fn packet_src(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        6 if packet.len() >= 40 => Some(IpAddr::V6(v6(&packet[8..24]))),
        _ => None,
    }
}

fn v6(bytes: &[u8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(bytes);
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0x45, 0, 0, 20];
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet
    }

    #[test]
    fn extracts_v4_addresses() {
        let pkt = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        assert_eq!(packet_src(&pkt), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(packet_dst(&pkt), Some("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn extracts_v6_addresses() {
        let mut pkt = vec![0x60, 0, 0, 0, 0, 0, 0, 0];
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        assert_eq!(packet_src(&pkt), Some(IpAddr::V6(src)));
        assert_eq!(packet_dst(&pkt), Some(IpAddr::V6(dst)));
    }

    #[test]
    fn rejects_short_and_unknown() {
        assert_eq!(packet_dst(&[]), None);
        assert_eq!(packet_dst(&[0x45, 0, 0]), None);
        assert_eq!(packet_dst(&[0x25, 0, 0, 0]), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn routes_packets_between_devices() {
        let private_a = PrivateKey::random();
        let public_a = private_a.public_key();
        let private_b = PrivateKey::random();
        let public_b = private_b.public_key();

        let device_a = Device::new("127.0.0.1:0".parse().unwrap(), private_a)
            .await
            .unwrap();
        let device_b = Device::new("127.0.0.1:0".parse().unwrap(), private_b)
            .await
            .unwrap();

        assert_eq!(device_a.public_key(), public_a);
        assert_eq!(device_b.public_key(), public_b);

        device_b
            .add_peer(
                &public_a,
                PeerConfig {
                    allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        device_a
            .add_peer(
                &public_b,
                PeerConfig {
                    allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        device_a
            .connect_peer(&public_b, device_b.local_addr().unwrap())
            .await
            .unwrap();

        let a_to_b = Bytes::from(ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]));
        let b_to_a = Bytes::from(ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]));
        assert!(matches!(
            device_a.send_packet(Bytes::from_static(b"invalid")).await,
            Err(DeviceError::InvalidPacket)
        ));
        assert!(matches!(
            device_a
                .send_packet(ipv4_packet([10, 0, 0, 1], [10, 0, 0, 3]))
                .await,
            Err(DeviceError::NoPeer(address))
                if address == "10.0.0.3".parse::<IpAddr>().unwrap()
        ));

        device_a.send_packet(a_to_b.clone()).await.unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), device_b.recv_packet())
                .await
                .expect("device B did not receive a packet")
                .unwrap();
        assert_eq!(received, a_to_b);

        device_b.send_packet(b_to_a.clone()).await.unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), device_a.recv_packet())
                .await
                .expect("device A did not receive a packet")
                .unwrap();
        assert_eq!(received, b_to_a);

        device_a
            .set_peer(
                &public_b,
                PeerConfig {
                    allowed_ips: vec!["10.0.0.3/32".parse().unwrap()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            device_a.send_packet(a_to_b).await,
            Err(DeviceError::NoPeer(address))
                if address == "10.0.0.2".parse::<IpAddr>().unwrap()
        ));

        let rerouted = Bytes::from(ipv4_packet([10, 0, 0, 1], [10, 0, 0, 3]));
        device_a.send_packet(rerouted.clone()).await.unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), device_b.recv_packet())
                .await
                .expect("device B did not receive a rerouted packet")
                .unwrap();
        assert_eq!(received, rerouted);

        let reconfigured_source = Bytes::from(ipv4_packet([10, 0, 0, 3], [10, 0, 0, 1]));
        device_b
            .send_packet(reconfigured_source.clone())
            .await
            .unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), device_a.recv_packet())
                .await
                .expect("device A did not accept the reconfigured source")
                .unwrap();
        assert_eq!(received, reconfigured_source);

        assert!(device_a.remove_peer(&public_b).await);
        assert!(!device_a.remove_peer(&public_b).await);
        assert!(device_a.peer(&public_b).is_none());
        assert!(matches!(
            device_a
                .connect_peer(&public_b, device_b.local_addr().unwrap())
                .await,
            Err(DeviceError::UnknownPeer(key)) if key == public_b
        ));
        assert!(matches!(
            device_a
                .set_peer(&public_b, PeerConfig::default())
                .await,
            Err(DeviceError::UnknownPeer(key)) if key == public_b
        ));
    }
}
