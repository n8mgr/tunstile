//! A packet-oriented WireGuard device with AllowedIPs routing and source
//! validation.
//!
//! # Example
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use tunstile::{Device, DeviceConfig, PeerConfig, PrivateKey, PublicKey};
//!
//! async fn start(
//!     private_key: PrivateKey,
//!     peer_key: PublicKey,
//!     endpoint: SocketAddr,
//! ) -> Device {
//!     let mut device = Device::new(
//!         "0.0.0.0:0".parse().unwrap(),
//!         DeviceConfig {
//!             private_key,
//!             mtu: None,
//!         },
//!     )
//!     .await
//!     .unwrap();
//!     device
//!         .add_peer(
//!             &peer_key,
//!             PeerConfig {
//!                 endpoint: Some(endpoint),
//!                 allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
//!                 ..Default::default()
//!             },
//!         )
//!         .await
//!         .unwrap();
//!     device
//! }
//! ```

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use log::debug;
use thiserror::Error;
use tunstile_tunnel::{
    MAX_PLAINTEXT_SIZE, Peer, PeerSender, RegisterError, TRANSPORT_PADDING_MULTIPLE, Tunnel,
};

mod allowed_ips;
mod config;
pub use config::{DeviceConfig, PeerConfig, PeerUpdate};
pub use ipnet::IpNet;
pub use tunstile_tunnel::{
    KeyParseError, PeerStatus, PresharedKey, PrivateKey, PublicKey, SendError, Update,
};

/// Error creating or operating a device.
#[derive(Debug, Error)]
pub enum DeviceError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("peer already registered")]
    AlreadyRegistered,

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
    max_packet_size: usize,
    peers: HashMap<PublicKey, Peer>,
    allowed_ips: allowed_ips::AllowedIps<PeerSender>,
}

impl Device {
    fn start(tunnel: Tunnel, max_packet_size: usize) -> Self {
        Self {
            tunnel,
            max_packet_size: max_packet_size.min(MAX_PLAINTEXT_SIZE),
            peers: HashMap::new(),
            allowed_ips: allowed_ips::AllowedIps::new(),
        }
    }

    /// Binds the UDP socket and creates a device with no peers.
    pub async fn new(listen_addr: SocketAddr, config: DeviceConfig) -> Result<Self, DeviceError> {
        let max_packet_size = config.mtu.unwrap_or(MAX_PLAINTEXT_SIZE);
        let tunnel = Tunnel::new(listen_addr, config.private_key).await?;
        Ok(Self::start(tunnel, max_packet_size))
    }

    /// Creates a device using an already-bound UDP socket.
    pub async fn from_socket(
        socket: std::net::UdpSocket,
        config: DeviceConfig,
    ) -> Result<Self, DeviceError> {
        let max_packet_size = config.mtu.unwrap_or(MAX_PLAINTEXT_SIZE);
        let tunnel = Tunnel::from_socket(socket, config.private_key).await?;
        Ok(Self::start(tunnel, max_packet_size))
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

    fn prepare_outbound_packet(&self, packet: &mut Vec<u8>) -> Option<IpAddr> {
        let Some(info) = packet_info(packet) else {
            debug!("dropping invalid outbound packet");
            return None;
        };
        packet.truncate(info.len);
        if !pad_packet(packet, self.max_packet_size) {
            debug!("dropping oversized outbound packet");
            return None;
        }
        Some(info.destination)
    }

    fn peer_for_destination(&self, destination: IpAddr) -> Option<PeerSender> {
        let sender = self.allowed_ips.longest_match(destination).cloned();
        if sender.is_none() {
            debug!("dropping outbound packet: no peer allows destination {destination}");
        }
        sender
    }

    /// Routes an outbound IP packet to the peer with the most-specific
    /// matching AllowedIP, waiting for space in that peer's send queue. The IP
    /// length is validated, trailing bytes are discarded, and the packet is
    /// zero-padded for WireGuard transport. Invalid, oversized, and unroutable
    /// packets are dropped and return `Ok(())`.
    pub async fn send_packet(&self, mut packet: Vec<u8>) -> Result<(), SendError> {
        let Some(destination) = self.prepare_outbound_packet(&mut packet) else {
            return Ok(());
        };
        let Some(sender) = self.peer_for_destination(destination) else {
            return Ok(());
        };
        sender.send(packet).await
    }

    /// Routes an outbound IP packet immediately, applying the same length
    /// validation and WireGuard padding as [`Device::send_packet`]. A full send
    /// queue, invalid or oversized packet, or missing route causes the packet
    /// to be dropped and return `Ok(())`.
    pub fn try_send_packet(&self, mut packet: Vec<u8>) -> Result<(), SendError> {
        let Some(destination) = self.prepare_outbound_packet(&mut packet) else {
            return Ok(());
        };
        let Some(sender) = self.peer_for_destination(destination) else {
            return Ok(());
        };
        match sender.try_send(packet) {
            Err(SendError::Full) => {
                debug!(
                    "dropping outbound packet for {}: send queue full",
                    sender.public_key()
                );
                Ok(())
            }
            Err(error) => Err(error),
            Ok(()) => Ok(()),
        }
    }

    /// Receives the next authenticated inbound IP packet after validating its
    /// declared length, removing WireGuard padding, and checking that its
    /// source address routes back to the delivering peer.
    pub async fn recv_packet(&mut self) -> Vec<u8> {
        loop {
            let packet = self.tunnel.recv().await;
            let mut payload = packet.payload;
            let Some(info) = packet_info(&payload) else {
                debug!("dropping invalid inbound packet");
                continue;
            };
            payload.truncate(info.len);
            let valid_source = self
                .allowed_ips
                .longest_match(info.source)
                .is_some_and(|sender| *sender.public_key() == packet.public_key);
            if !valid_source {
                debug!(
                    "inbound packet from unexpected source {}; dropping",
                    info.source
                );
                continue;
            }
            return payload;
        }
    }

    /// Registers a peer and its AllowedIPs.
    pub async fn add_peer(
        &mut self,
        public_key: &PublicKey,
        config: PeerConfig,
    ) -> Result<(), DeviceError> {
        if self.peers.contains_key(public_key) {
            return Err(DeviceError::AlreadyRegistered);
        }
        let (tunnel_config, peer_allowed_ips) = config.take_tunnel();
        let peer = self
            .tunnel
            .add_peer(public_key, tunnel_config)
            .await
            .map_err(|error| match error {
                RegisterError::AlreadyRegistered => DeviceError::AlreadyRegistered,
            })?;
        let sender = peer.sender();
        for net in peer_allowed_ips {
            self.allowed_ips.insert(net, sender.clone());
        }
        let previous = self.peers.insert(public_key.clone(), peer);
        debug_assert!(previous.is_none());
        Ok(())
    }

    /// Applies explicit updates to a registered peer without unregistering
    /// it or discarding protocol state.
    pub async fn set_peer(
        &mut self,
        public_key: &PublicKey,
        update: PeerUpdate,
    ) -> Result<(), DeviceError> {
        let sender = self
            .peers
            .get(public_key)
            .map(Peer::sender)
            .ok_or_else(|| DeviceError::UnknownPeer(public_key.clone()))?;

        let (tunnel_update, allowed_ips) = update.take_tunnel();
        self.tunnel.set_peer(public_key, tunnel_update).await?;

        match allowed_ips {
            Update::Keep => {}
            Update::Clear => self
                .allowed_ips
                .retain(|owner| owner.public_key() != public_key),
            Update::Set(nets) => {
                self.allowed_ips
                    .retain(|owner| owner.public_key() != public_key);
                for net in nets {
                    self.allowed_ips.insert(net, sender.clone());
                }
            }
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
        let peer = self
            .peers
            .get(public_key)
            .ok_or_else(|| DeviceError::UnknownPeer(public_key.clone()))?;
        peer.connect(endpoint).await?;
        Ok(())
    }

    /// Unregisters a peer and removes its AllowedIPs.
    pub fn remove_peer(&mut self, public_key: &PublicKey) -> bool {
        if self.peers.remove(public_key).is_none() {
            return false;
        }
        self.allowed_ips
            .retain(|sender| sender.public_key() != public_key);
        true
    }
}

struct PacketInfo {
    source: IpAddr,
    destination: IpAddr,
    len: usize,
}

fn pad_packet(packet: &mut Vec<u8>, max_packet_size: usize) -> bool {
    if packet.len() > max_packet_size {
        return false;
    }
    let padded_len = packet.len().next_multiple_of(TRANSPORT_PADDING_MULTIPLE);
    let padded_len = padded_len.min(max_packet_size);
    packet.resize(padded_len, 0);
    true
}

fn packet_info(packet: &[u8]) -> Option<PacketInfo> {
    let version = packet.first()? >> 4;
    match version {
        4 if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header_len < 20 || len < header_len || len > packet.len() {
                return None;
            }
            Some(PacketInfo {
                source: IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                destination: IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                )),
                len,
            })
        }
        6 if packet.len() >= 40 => {
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let len = 40usize.checked_add(payload_len)?;
            if len > packet.len() {
                return None;
            }
            Some(PacketInfo {
                source: IpAddr::V6(v6(&packet[8..24])),
                destination: IpAddr::V6(v6(&packet[24..40])),
                len,
            })
        }
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

    fn packet_dst(packet: &[u8]) -> Option<IpAddr> {
        packet_info(packet).map(|info| info.destination)
    }

    fn packet_src(packet: &[u8]) -> Option<IpAddr> {
        packet_info(packet).map(|info| info.source)
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0x45, 0, 0, 20];
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet
    }

    fn ipv6_packet(source: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&source.octets());
        packet.extend_from_slice(&destination.octets());
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
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        let pkt = ipv6_packet(src, dst);
        assert_eq!(packet_src(&pkt), Some(IpAddr::V6(src)));
        assert_eq!(packet_dst(&pkt), Some(IpAddr::V6(dst)));
    }

    #[test]
    fn pads_and_trims_ipv4_packets() {
        let mut original = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        original.extend_from_slice(b"payload");
        let original_len = original.len() as u16;
        original[2..4].copy_from_slice(&original_len.to_be_bytes());

        let mut packet = original.clone();
        assert!(pad_packet(&mut packet, MAX_PLAINTEXT_SIZE));
        assert_eq!(packet.len() % TRANSPORT_PADDING_MULTIPLE, 0);
        assert_eq!(&packet[..original.len()], original);
        assert!(packet[original.len()..].iter().all(|byte| *byte == 0));

        let info = packet_info(&packet).unwrap();
        packet.truncate(info.len);
        assert_eq!(packet, original);
    }

    #[test]
    fn pads_and_trims_ipv6_packets() {
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        let mut original = ipv6_packet(src, dst);
        original.extend_from_slice(b"payload");
        original[4..6].copy_from_slice(&7u16.to_be_bytes());

        let mut packet = original.clone();
        assert!(pad_packet(&mut packet, MAX_PLAINTEXT_SIZE));
        assert_eq!(packet.len() % TRANSPORT_PADDING_MULTIPLE, 0);
        assert!(packet[original.len()..].iter().all(|byte| *byte == 0));

        let info = packet_info(&packet).unwrap();
        packet.truncate(info.len);
        assert_eq!(packet, original);
    }

    #[test]
    fn padding_does_not_exceed_the_inner_mtu() {
        let mut packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        packet.extend_from_slice(b"payload");
        packet[2..4].copy_from_slice(&27u16.to_be_bytes());

        assert!(pad_packet(&mut packet, 30));
        assert_eq!(packet.len(), 30);
        assert!(packet[27..].iter().all(|byte| *byte == 0));

        assert!(!pad_packet(&mut packet, 26));
    }

    #[test]
    fn rejects_short_and_unknown() {
        assert_eq!(packet_dst(&[]), None);
        assert_eq!(packet_dst(&[0x45, 0, 0]), None);
        assert_eq!(packet_dst(&[0x25, 0, 0, 0]), None);

        let mut invalid_ihl = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        invalid_ihl[0] = 0x44;
        assert!(packet_info(&invalid_ihl).is_none());

        let mut invalid_v4_len = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        invalid_v4_len[2..4].copy_from_slice(&21u16.to_be_bytes());
        assert!(packet_info(&invalid_v4_len).is_none());

        let mut invalid_v6_len = ipv6_packet(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST);
        invalid_v6_len[4..6].copy_from_slice(&1u16.to_be_bytes());
        assert!(packet_info(&invalid_v6_len).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn routes_packets_between_devices() {
        let private_a = PrivateKey::random();
        let public_a = private_a.public_key();
        let private_b = PrivateKey::random();
        let public_b = private_b.public_key();

        let mut device_a = Device::new(
            "127.0.0.1:0".parse().unwrap(),
            DeviceConfig {
                private_key: private_a,
                mtu: None,
            },
        )
        .await
        .unwrap();
        let mut device_b = Device::new(
            "127.0.0.1:0".parse().unwrap(),
            DeviceConfig {
                private_key: private_b,
                mtu: None,
            },
        )
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

        let a_to_b = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        let b_to_a = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]);
        assert_eq!(device_a.send_packet(b"invalid".to_vec()).await, Ok(()));
        assert_eq!(
            device_a
                .send_packet(ipv4_packet([10, 0, 0, 1], [10, 0, 0, 3]))
                .await,
            Ok(())
        );

        device_a.send_packet(a_to_b.clone()).await.unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), device_b.recv_packet())
                .await
                .expect("device B did not receive a packet");
        assert_eq!(received, a_to_b);

        device_b.send_packet(b_to_a.clone()).await.unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), device_a.recv_packet())
                .await
                .expect("device A did not receive a packet");
        assert_eq!(received, b_to_a);

        device_a
            .set_peer(
                &public_b,
                PeerUpdate {
                    allowed_ips: Update::Set(vec!["10.0.0.3/32".parse().unwrap()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(device_a.send_packet(a_to_b).await, Ok(()));

        let rerouted = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 3]);
        device_a.send_packet(rerouted.clone()).await.unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), device_b.recv_packet())
                .await
                .expect("device B did not receive a rerouted packet");
        assert_eq!(received, rerouted);

        let reconfigured_source = ipv4_packet([10, 0, 0, 3], [10, 0, 0, 1]);
        device_b
            .send_packet(reconfigured_source.clone())
            .await
            .unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), device_a.recv_packet())
                .await
                .expect("device A did not accept the reconfigured source");
        assert_eq!(received, reconfigured_source);

        assert!(device_a.remove_peer(&public_b));
        assert!(!device_a.remove_peer(&public_b));
        assert!(device_a.peer(&public_b).is_none());
        assert!(matches!(
            device_a
                .connect_peer(&public_b, device_b.local_addr().unwrap())
                .await,
            Err(DeviceError::UnknownPeer(key)) if key == public_b
        ));
        assert!(matches!(
            device_a
                .set_peer(&public_b, PeerUpdate::default())
                .await,
            Err(DeviceError::UnknownPeer(key)) if key == public_b
        ));
    }
}
