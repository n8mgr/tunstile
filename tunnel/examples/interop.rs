use clap::Parser;
use etherparse::PacketBuilder;
use std::{net::SocketAddr, time::Duration};
use tokio::time::{Instant, interval, sleep_until};
use tunstile_tunnel::{PeerConfig, PrivateKey, PublicKey, Tunnel};

/// Exercises a tunstile tunnel against a reference WireGuard peer
/// (testutil/interop). Set RUST_LOG=debug for tunnel internals.
#[derive(Parser)]
struct Args {
    /// our private key (base64)
    #[arg(long, default_value = "anf/KiKfSTcqiSDmCP9qBmrS4nYq39/3cBjmGwx/6DM=")]
    key: PrivateKey,

    /// peer public key (base64)
    #[arg(long, default_value = "jrpP5X9mNSxjkd6tCnHwdRI4Rp8ZnquQj34UAqlZpx8=")]
    peer: PublicKey,

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

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    println!("rust public key: {}", args.key.public_key());

    let mut tunnel = Tunnel::new(args.bind, args.key.clone()).await.unwrap();
    let peer = tunnel
        .add_peer(
            &args.peer,
            PeerConfig {
                endpoint: Some(args.endpoint),
                ..Default::default()
            },
        )
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
            packet = tunnel.recv() => {
                println!(
                    "[{:>3}s] recv {} bytes: {}",
                    started.elapsed().as_secs(),
                    packet.payload.len(),
                    String::from_utf8_lossy(&packet.payload)
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
