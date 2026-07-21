//! A user-space implementation of Wireguard using tunstile

use std::{
    fs, io,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};

use base64::{Engine, prelude::BASE64_STANDARD};
use bytes::{Bytes, BytesMut};
use clap::Parser;
use ipnet::IpNet;
use tun::{AbstractDevice, AsyncDevice};
use tunstile::{Device, DeviceError, PeerConfig, PrivateKey, PublicKey, SendError};

/// Bring up a WireGuard interface from a wg-quick style config file.
#[derive(Parser)]
struct Args {
    /// path to the interface config (.conf)
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    let text = fs::read_to_string(&args.config)
        .unwrap_or_else(|e| fail(format!("reading {}: {e}", args.config.display())));
    let (listen_addr, private_key, tun_config, peer_configs) = parse_config(&text)
        .unwrap_or_else(|e| fail(format!("parsing {}: {e}", args.config.display())));

    println!("public key: {}", private_key.public_key());
    let device = Device::new(listen_addr, private_key)
        .await
        .unwrap_or_else(|e| fail(format!("creating device: {e}")));
    let packets = TunPackets::new(&tun_config)
        .unwrap_or_else(|e| fail(format!("bringing up interface: {e}")));
    let tun_name = packets
        .tun_name()
        .unwrap_or_else(|| fail("interface has no name".into()));

    let peer_count = peer_configs.len();
    for (key, peer) in peer_configs {
        let allowed_ips = peer.allowed_ips.clone();
        device
            .add_peer(&key, peer)
            .await
            .unwrap_or_else(|e| fail(format!("adding peer {key}: {e}")));
        add_routes(&tun_name, &allowed_ips)
            .unwrap_or_else(|e| fail(format!("routing peer {key}: {e}")));
    }
    println!("{tun_name} up with {peer_count} peer(s); ctrl-c to stop");

    tokio::select! {
        result = run_packets(&device, &packets) => match result {
            Ok(()) => println!("packet interface closed"),
            Err(error) => fail(format!("packet interface: {error}")),
        },
        _ = tokio::signal::ctrl_c() => println!("shutting down"),
    }
}

fn fail(msg: String) -> ! {
    eprintln!("tunstile: {msg}");
    std::process::exit(1);
}

#[derive(Default)]
struct PeerSection {
    public_key: Option<PublicKey>,
    endpoint: Option<SocketAddr>,
    preshared_key: Option<[u8; 32]>,
    keepalive: Option<u64>,
    allowed_ips: Vec<IpNet>,
}

struct TunConfig {
    address: IpNet,
    mtu: u16,
}

struct TunPackets {
    tun: AsyncDevice,
    mtu: usize,
}

impl TunPackets {
    fn new(config: &TunConfig) -> io::Result<Self> {
        let mut tun_config = tun::Configuration::default();
        tun_config
            .address(config.address.addr())
            .netmask(config.address.netmask())
            .mtu(config.mtu)
            .up();
        let tun = tun::create_as_async(&tun_config).map_err(io::Error::from)?;
        Ok(Self {
            tun,
            mtu: config.mtu as usize,
        })
    }

    fn tun_name(&self) -> Option<String> {
        self.tun.tun_name().ok().filter(|name| !name.is_empty())
    }

    async fn recv(&self) -> io::Result<Bytes> {
        let mut packet = BytesMut::with_capacity(self.mtu);
        packet.resize(self.mtu, 0);
        let len = self.tun.recv(&mut packet).await?;
        packet.truncate(len);
        Ok(packet.freeze())
    }

    async fn send(&self, packet: Bytes) -> io::Result<()> {
        self.tun.send(&packet).await.map(|_| ())
    }
}

async fn run_packets(device: &Device, packets: &TunPackets) -> Result<(), DeviceError> {
    let recv = packets.recv();
    tokio::pin!(recv);
    loop {
        tokio::select! {
            packet = &mut recv => {
                match device.try_send_packet(packet?) {
                    Ok(()) => {}
                    Err(error @ (
                        DeviceError::InvalidPacket
                        | DeviceError::NoPeer(_)
                        | DeviceError::Send(SendError::Full)
                    )) => {
                        log::debug!("dropping outbound packet: {error}");
                    }
                    Err(error) => return Err(error),
                }
                recv.set(packets.recv());
            }
            packet = device.recv_packet() => {
                let Some(packet) = packet else {
                    return Ok(());
                };
                packets.send(packet).await?;
            }
        }
    }
}

type ParsedConfig = (
    SocketAddr,
    PrivateKey,
    TunConfig,
    Vec<(PublicKey, PeerConfig)>,
);

fn parse_config(text: &str) -> Result<ParsedConfig, String> {
    let mut section = String::new();
    let mut private_key = None;
    let mut address = None;
    let mut listen_port: u16 = 51820;
    let mut mtu = None;
    let mut peers: Vec<PeerSection> = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let at = |what: &str| format!("line {}: {what}", i + 1);

        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            if section == "peer" {
                peers.push(PeerSection::default());
            }
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| at("expected key = value"))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match (section.as_str(), key.as_str()) {
            ("interface", "privatekey") => {
                private_key = Some(value.parse().map_err(|_| at("invalid PrivateKey"))?);
            }
            ("interface", "address") => {
                let first = value.split(',').next().unwrap().trim();
                address = Some(first.parse().map_err(|_| at("invalid Address"))?);
            }
            ("interface", "listenport") => {
                listen_port = value.parse().map_err(|_| at("invalid ListenPort"))?;
            }
            ("interface", "mtu") => {
                mtu = Some(value.parse().map_err(|_| at("invalid MTU"))?);
            }
            ("peer", _) => {
                let peer = peers.last_mut().ok_or_else(|| at("key outside a [Peer]"))?;
                match key.as_str() {
                    "publickey" => {
                        peer.public_key = Some(value.parse().map_err(|_| at("invalid PublicKey"))?);
                    }
                    "presharedkey" => {
                        peer.preshared_key =
                            Some(decode_key(value).map_err(|_| at("invalid PresharedKey"))?);
                    }
                    "endpoint" => {
                        peer.endpoint = Some(resolve(value).map_err(|e| at(&e))?);
                    }
                    "allowedips" => {
                        for cidr in value.split(',') {
                            let cidr = cidr.trim();
                            if cidr.is_empty() {
                                continue;
                            }
                            peer.allowed_ips
                                .push(cidr.parse().map_err(|_| at("invalid AllowedIPs"))?);
                        }
                    }
                    "persistentkeepalive" => {
                        peer.keepalive = Some(
                            value
                                .parse()
                                .map_err(|_| at("invalid PersistentKeepalive"))?,
                        );
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    let private_key = private_key.ok_or("[Interface] missing PrivateKey")?;
    let address = address.ok_or("[Interface] missing Address")?;
    let listen_addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let tun_config = TunConfig {
        address,
        mtu: mtu.unwrap_or(1420),
    };

    let mut peer_configs = Vec::new();
    for peer in peers {
        let public_key = peer.public_key.ok_or("[Peer] missing PublicKey")?;
        peer_configs.push((
            public_key,
            PeerConfig {
                endpoint: peer.endpoint,
                preshared_key: peer.preshared_key,
                persistent_keepalive: peer.keepalive.map(Duration::from_secs),
                allowed_ips: peer.allowed_ips,
            },
        ));
    }
    Ok((listen_addr, private_key, tun_config, peer_configs))
}

fn decode_key(s: &str) -> Result<[u8; 32], ()> {
    let bytes = BASE64_STANDARD.decode(s).map_err(|_| ())?;
    <[u8; 32]>::try_from(bytes).map_err(|_| ())
}

fn resolve(endpoint: &str) -> Result<SocketAddr, String> {
    endpoint
        .to_socket_addrs()
        .map_err(|e| format!("resolving Endpoint {endpoint}: {e}"))?
        .next()
        .ok_or_else(|| format!("Endpoint {endpoint} resolved to no addresses"))
}

// WireGuard's userspace tools install these out of band (wg-quick); the kernel
// won't send matching traffic to the interface otherwise. The routes vanish
// with the interface when the process exits.
#[cfg(target_os = "macos")]
fn add_routes(tun_name: &str, nets: &[IpNet]) -> Result<(), String> {
    use std::process::Command;
    for net in nets {
        let cidr = net.to_string();
        // clear any stale route, then add fresh; the delete is expected to
        // fail when nothing is there
        let _ = Command::new("route")
            .args(["-qn", "delete", "-net", &cidr, "-interface", tun_name])
            .output();
        let out = Command::new("route")
            .args(["-qn", "add", "-net", &cidr, "-interface", tun_name])
            .output()
            .map_err(|e| format!("route add {cidr} -> {tun_name}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "route add {cidr} -> {tun_name}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        log::info!("routing {cidr} via {tun_name}");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn add_routes(_tun_name: &str, _nets: &[IpNet]) -> Result<(), String> {
    log::warn!("automatic route installation is only implemented on macOS");
    Ok(())
}
