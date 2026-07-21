use std::{net::SocketAddr, time::Duration};

use ipnet::IpNet;
use tunstile_tunnel::{PrivateKey, PublicKey};

/// A peer and its allowed IP prefixes.
#[derive(Clone)]
pub struct PeerConfig {
    pub(crate) public_key: PublicKey,
    pub(crate) endpoint: Option<SocketAddr>,
    pub(crate) preshared_key: Option<[u8; 32]>,
    pub(crate) persistent_keepalive: Option<Duration>,
    pub(crate) allowed_ips: Vec<IpNet>,
}

impl PeerConfig {
    /// A config for the peer with the given public key and no AllowedIPs.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            endpoint: None,
            preshared_key: None,
            persistent_keepalive: None,
            allowed_ips: Vec::new(),
        }
    }

    /// Sets the peer's initial endpoint.
    pub fn endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Sets the optional pre-shared key.
    pub fn preshared_key(mut self, preshared_key: [u8; 32]) -> Self {
        self.preshared_key = Some(preshared_key);
        self
    }

    /// Sets the persistent keepalive interval.
    pub fn persistent_keepalive(mut self, interval: Duration) -> Self {
        self.persistent_keepalive = Some(interval);
        self
    }

    /// Adds an allowed IP prefix for this peer.
    pub fn allowed_ip(mut self, net: IpNet) -> Self {
        self.allowed_ips.push(net);
        self
    }

    /// The peer's public key.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// This peer's allowed IP prefixes.
    pub fn allowed_ips(&self) -> &[IpNet] {
        &self.allowed_ips
    }

    pub(crate) fn to_tunnel(&self) -> tunstile_tunnel::PeerConfig {
        let mut cfg = tunstile_tunnel::PeerConfig::new(self.public_key);
        if let Some(endpoint) = self.endpoint {
            cfg = cfg.endpoint(endpoint);
        }
        if let Some(psk) = self.preshared_key {
            cfg = cfg.preshared_key(psk);
        }
        if let Some(interval) = self.persistent_keepalive {
            cfg = cfg.persistent_keepalive(interval);
        }
        cfg
    }
}

/// The local interface parameters. Peers are added at runtime with
/// [`Device::add_peer`](crate::Device::add_peer), not baked in here.
pub struct DeviceConfig {
    pub(crate) private_key: PrivateKey,
    pub(crate) address: IpNet,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) mtu: u16,
}

impl DeviceConfig {
    /// A config with the given private key and interface address, an ephemeral
    /// listen port, and the default 1420-byte MTU.
    pub fn new(private_key: PrivateKey, address: IpNet) -> Self {
        Self {
            private_key,
            address,
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            mtu: 1420,
        }
    }

    /// UDP address the tunnel binds for outer traffic. Defaults to an
    /// ephemeral port on all interfaces.
    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }

    /// Sets the interface MTU.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Our public key, derived from the private key.
    pub fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }
}
