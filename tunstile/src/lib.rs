//! A WireGuard device combining a TUN interface, AllowedIPs routing and source
//! validation, and [tunstile_tunnel].
//!
//! # Example
//!
//! ```no_run
//! use std::{error::Error, net::SocketAddr};
//! use tunstile::{Device, DeviceConfig, DevicePeer, PeerConfig, PrivateKey, PublicKey};
//!
//! async fn start(
//!     private_key: PrivateKey,
//!     peer_key: PublicKey,
//!     endpoint: SocketAddr,
//! ) -> Result<(Device, DevicePeer), Box<dyn Error>> {
//!     let config = DeviceConfig::new(private_key, "10.0.0.2/32".parse()?);
//!     let device = Device::new(config).await?;
//!     let peer = device
//!         .add_peer(
//!             PeerConfig::new(peer_key)
//!                 .endpoint(endpoint)
//!                 .allowed_ip("0.0.0.0/0".parse()?),
//!         )
//!         .await?;
//!     Ok((device, peer))
//! }
//! ```

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{IntoRawFd, OwnedFd},
    sync::{Arc, RwLock},
};

use bytes::BytesMut;
use log::debug;
use thiserror::Error;
use tokio::{spawn, task::JoinHandle};
use tun::{AbstractDevice, AsyncDevice};
use tunstile_tunnel::{Peer, PeerSender, RegisterError, SendError, Tunnel};

mod allowed_ips;
mod config;
pub use config::{DeviceConfig, PeerConfig};
pub use ipnet;
pub use tunstile_tunnel::{PeerStatus, PrivateKey, PublicKey};

type AllowedIpTable = Arc<RwLock<allowed_ips::AllowedIps<PeerSender>>>;

/// Error bringing up a device or adding a peer.
#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("tun interface error: {0}")]
    Tun(#[from] tun::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("duplicate peer")]
    DuplicatePeer(#[from] RegisterError),

    #[error("interface address {0} is not an IPv4 address")]
    UnsupportedAddress(IpAddr),
}

/// A WireGuard interface. Owns the TUN device and the outbound datapath;
/// peers are added at runtime with [`Device::add_peer`] and removed by
/// dropping the returned [`DevicePeer`].
///
/// # Example
///
/// ```no_run
/// use tunstile::{Device, DeviceConfig, PeerConfig, PrivateKey};
///
/// # async fn start() -> Result<(), Box<dyn std::error::Error>> {
/// let config = DeviceConfig::new(PrivateKey::random(), "10.0.0.2/32".parse()?);
/// let device = Device::new(config).await?;
/// let peer = PeerConfig::new(
///     "jrpP5X9mNSxjkd6tCnHwdRI4Rp8ZnquQj34UAqlZpx8=".parse()?,
/// )
/// .endpoint("203.0.113.1:51820".parse()?)
/// .allowed_ip("10.1.0.0/16".parse()?);
/// let _peer = device.add_peer(peer).await?;
/// # Ok(())
/// # }
/// ```
pub struct Device {
    tunnel: Tunnel,
    tun: Arc<AsyncDevice>,
    allowed_ips: AllowedIpTable,
    outbound: JoinHandle<()>,
}

impl Drop for Device {
    fn drop(&mut self) {
        self.outbound.abort();
    }
}

impl Device {
    /// The name of the created TUN interface (e.g. `utun4`), or `None` when
    /// the device wraps an externally created fd.
    pub fn tun_name(&self) -> Option<String> {
        self.tun.tun_name().ok().filter(|n| !n.is_empty())
    }

    /// Status snapshots for every registered peer.
    pub fn peers(&self) -> Vec<PeerStatus> {
        self.tunnel.peers()
    }

    /// Status snapshot for one peer, or `None` if it isn't registered.
    pub fn peer(&self, public_key: &PublicKey) -> Option<PeerStatus> {
        self.tunnel.peer(public_key)
    }

    /// Brings up the TUN interface and starts the tunnel with no peers.
    pub async fn new(config: DeviceConfig) -> Result<Self, DeviceError> {
        let IpAddr::V4(addr) = config.address.addr() else {
            return Err(DeviceError::UnsupportedAddress(config.address.addr()));
        };
        let netmask = Ipv4Addr::from(
            u32::MAX
                .checked_shl(32 - config.address.prefix_len() as u32)
                .unwrap_or(0),
        );

        let mut tun_config = tun::Configuration::default();
        tun_config
            .address(addr)
            .netmask(netmask)
            .mtu(config.mtu)
            .up();
        let tun = tun::create_as_async(&tun_config)?;
        Self::start(tun, config).await
    }

    /// Wraps an externally created TUN fd — e.g. detached from Android's
    /// `VpnService` — and starts the tunnel with no peers. Takes ownership of
    /// the fd; it is closed when the device is dropped. The config's address
    /// is not applied and its MTU only sizes internal buffers; the embedder
    /// owns the interface's configuration.
    pub async fn from_fd(fd: OwnedFd, config: DeviceConfig) -> Result<Self, DeviceError> {
        let mut tun_config = tun::Configuration::default();
        tun_config.raw_fd(fd.into_raw_fd()).mtu(config.mtu);
        let tun = tun::create_as_async(&tun_config)?;
        Self::start(tun, config).await
    }

    async fn start(tun: AsyncDevice, config: DeviceConfig) -> Result<Self, DeviceError> {
        let tun = Arc::new(tun);
        let tunnel = Tunnel::new(config.listen_addr, config.private_key).await?;
        let allowed_ips: AllowedIpTable = Arc::new(RwLock::new(allowed_ips::AllowedIps::new()));
        let outbound = spawn(outbound_loop(
            tun.clone(),
            allowed_ips.clone(),
            config.mtu as usize,
        ));

        Ok(Self {
            tunnel,
            tun,
            allowed_ips,
            outbound,
        })
    }

    /// Registers a peer, adds its allowed IPs to cryptokey routing, and
    /// starts delivering its inbound packets. The peer stays active until
    /// the returned handle is dropped. Installing OS routes for the allowed
    /// IPs is the caller's job.
    pub async fn add_peer(&self, config: PeerConfig) -> Result<DevicePeer, DeviceError> {
        let peer = self.tunnel.add_peer(config.to_tunnel()).await?;
        let sender = peer.sender();
        {
            let mut allowed_ips = self.allowed_ips.write().unwrap();
            for net in &config.allowed_ips {
                allowed_ips.insert(*net, sender.clone());
            }
        }
        let task = spawn(inbound_loop(
            self.tun.clone(),
            self.allowed_ips.clone(),
            peer,
        ));
        Ok(DevicePeer {
            public_key: config.public_key,
            sender,
            allowed_ips: self.allowed_ips.clone(),
            task,
        })
    }
}

/// A registered peer. Dropping it unregisters the peer, removes its
/// AllowedIPs entries, and stops delivering its packets.
#[must_use = "dropping the DevicePeer removes the peer and its AllowedIPs"]
pub struct DevicePeer {
    public_key: PublicKey,
    sender: PeerSender,
    allowed_ips: AllowedIpTable,
    task: JoinHandle<()>,
}

impl Drop for DevicePeer {
    fn drop(&mut self) {
        // aborting the inbound task drops the tunnel Peer, unregistering it
        self.task.abort();
        self.allowed_ips
            .write()
            .unwrap()
            .retain(|s| s.public_key() != self.public_key);
    }
}

impl DevicePeer {
    /// This peer's public key.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Current status snapshot for this peer.
    pub fn status(&self) -> Option<PeerStatus> {
        self.sender.status()
    }

    /// Updates the peer's endpoint (e.g. after a DNS re-resolve) and
    /// initiates a handshake if none is in flight.
    pub async fn connect(&self, endpoint: SocketAddr) -> Result<(), SendError> {
        self.sender.connect(endpoint).await
    }
}

async fn outbound_loop(tun: Arc<AsyncDevice>, allowed_ips: AllowedIpTable, mtu: usize) {
    let mut buf = BytesMut::with_capacity(mtu);
    loop {
        buf.resize(mtu, 0);
        let n = match tun.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                debug!("tun recv failed: {:?}", e);
                continue;
            }
        };
        buf.truncate(n);
        let packet = buf.split().freeze();
        let Some(dst) = packet_dst(&packet) else {
            continue;
        };
        let sender = allowed_ips.read().unwrap().longest_match(dst).cloned();
        let Some(sender) = sender else {
            debug!("no peer for destination {dst}; dropping");
            continue;
        };
        let _ = sender.send(packet).await;
    }
}

async fn inbound_loop(tun: Arc<AsyncDevice>, allowed_ips: AllowedIpTable, mut peer: Peer) {
    let peer_key = peer.public_key();
    while let Some(packet) = peer.recv().await {
        let Some(src) = packet_src(&packet) else {
            continue;
        };
        // anti-spoofing: the source's most-specific AllowedIP must belong to
        // the sending peer
        let owner = allowed_ips
            .read()
            .unwrap()
            .longest_match(src)
            .map(|s| s.public_key());
        if owner != Some(peer_key) {
            debug!("inbound packet from unexpected source {src}; dropping");
            continue;
        }
        if let Err(e) = tun.send(&packet).await {
            debug!("tun send failed: {:?}", e);
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

    #[test]
    fn extracts_v4_addresses() {
        let mut pkt = vec![0x45, 0, 0, 20];
        pkt.extend_from_slice(&[0; 8]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
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
}
