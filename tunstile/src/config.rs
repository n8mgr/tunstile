use std::{net::SocketAddr, time::Duration};

use ipnet::IpNet;
use tunstile_tunnel::{PresharedKey, PrivateKey};

/// Settings for a [`crate::Device`].
#[derive(Clone, Debug)]
pub struct DeviceConfig {
    /// The device's WireGuard private key.
    pub private_key: PrivateKey,

    /// The platform interface's inner MTU. When set, packets larger than this
    /// are dropped and WireGuard padding will not grow packets beyond it.
    pub mtu: Option<usize>,
}

/// Optional settings and allowed IP prefixes for a peer.
#[derive(Clone, Debug, Default)]
pub struct PeerConfig {
    /// The peer's initial or replacement endpoint. When passed to
    /// [`crate::Device::set_peer`], `None` keeps the current endpoint.
    pub endpoint: Option<SocketAddr>,

    /// The optional pre-shared key.
    pub preshared_key: Option<PresharedKey>,

    /// The persistent keepalive interval.
    pub persistent_keepalive: Option<Duration>,

    /// IP prefixes routed to and accepted from this peer.
    pub allowed_ips: Vec<IpNet>,
}

impl PeerConfig {
    pub(crate) fn take_tunnel(mut self) -> (tunstile_tunnel::PeerConfig, Vec<IpNet>) {
        (
            tunstile_tunnel::PeerConfig {
                endpoint: self.endpoint,
                preshared_key: self.preshared_key.take(),
                persistent_keepalive: self.persistent_keepalive,
            },
            self.allowed_ips,
        )
    }
}
