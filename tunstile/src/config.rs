use std::{net::SocketAddr, time::Duration};

use ipnet::IpNet;

/// Optional settings and allowed IP prefixes for a peer.
#[derive(Clone, Debug, Default)]
pub struct PeerConfig {
    /// The peer's initial or replacement endpoint. When passed to
    /// [`crate::Device::set_peer`], `None` keeps the current endpoint.
    pub endpoint: Option<SocketAddr>,

    /// The optional pre-shared key.
    pub preshared_key: Option<[u8; 32]>,

    /// The persistent keepalive interval.
    pub persistent_keepalive: Option<Duration>,

    /// IP prefixes routed to and accepted from this peer.
    pub allowed_ips: Vec<IpNet>,
}

impl PeerConfig {
    pub(crate) fn to_tunnel(&self) -> tunstile_tunnel::PeerConfig {
        tunstile_tunnel::PeerConfig {
            endpoint: self.endpoint,
            preshared_key: self.preshared_key,
            persistent_keepalive: self.persistent_keepalive,
        }
    }
}
