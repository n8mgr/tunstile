use clap::Parser;
use etherparse::PacketBuilder;
use spacetun_tunnel::{PublicKey, StaticSecret, Tunnel};
use std::{net::SocketAddr, time::Duration};
use tokio::time::{Instant, interval, sleep_until};

/// Exercises a spacetun tunnel against a reference WireGuard peer
/// (testutil/interop). Set RUST_LOG=debug for tunnel internals.
#[derive(Parser)]
struct Args {
    /// our private key (hex)
    #[arg(
        long,
        default_value = "6a77ff2a229f49372a8920e608ff6a066ad2e2762adfdff77018e61b0c7fe833"
    )]
    key: String,

    /// peer public key (hex)
    #[arg(
        long,
        default_value = "8eba4fe57f66352c6391dead0a71f0751238469f199eab908f7e1402a959a71f"
    )]
    peer: String,

    #[arg(long, default_value = "127.0.0.1:51820")]
    bind: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:51821")]
    endpoint: SocketAddr,

    /// run time in seconds; the default crosses Rekey-After-Time (120s)
    #[arg(long, default_value_t = 200)]
    duration: u64,

    /// seconds between pings
    #[arg(long, default_value_t = 20)]
    ping_interval: u64,
}

fn key_bytes(s: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(hex::decode(s).expect("invalid hex key")).expect("key must be 32 bytes")
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    let our_private = StaticSecret::from(key_bytes(&args.key));
    println!(
        "rust public key (hex): {}",
        hex::encode(PublicKey::from(&our_private).as_bytes())
    );
    let peer_public = PublicKey::from(key_bytes(&args.peer));

    let tunnel = Tunnel::new(args.bind, our_private).await.unwrap();
    let mut peer = tunnel
        .connect_peer(peer_public, args.endpoint)
        .await
        .unwrap();
    println!("sent handshake init; waiting for handshake to complete");
    peer.ready().await.unwrap();
    println!("handshake complete");

    let started = Instant::now();
    let end = started + Duration::from_secs(args.duration);
    let mut ping = interval(Duration::from_secs(args.ping_interval));
    let mut seq = 0u32;
    loop {
        tokio::select! {
            _ = sleep_until(end) => break,
            _ = ping.tick() => {
                seq += 1;
                let payload = format!("ping {seq} from rust");
                let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(12345, 12345);
                let mut ip_pkt = Vec::new();
                builder.write(&mut ip_pkt, payload.as_bytes()).unwrap();
                peer.send(ip_pkt).await.unwrap();
                let status = peer.status();
                println!(
                    "[{:>3}s] sent {payload:?} (tx {} rx {})",
                    started.elapsed().as_secs(),
                    status.tx_bytes,
                    status.rx_bytes
                );
            }
            data = peer.recv() => {
                let Some(data) = data else {
                    println!("peer closed");
                    break;
                };
                println!(
                    "[{:>3}s] recv {} bytes: {}",
                    started.elapsed().as_secs(),
                    data.len(),
                    String::from_utf8_lossy(&data)
                );
            }
        }
    }

    let status = peer.status();
    println!(
        "done: tx {} rx {} last_handshake {:?}",
        status.tx_bytes, status.rx_bytes, status.last_successful_handshake
    );
}
