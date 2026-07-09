use etherparse::PacketBuilder;
use spacetun_tunnel::{PublicKey, StaticSecret, Tunnel};
use std::{net::SocketAddr, time::Duration};
use tokio::time::{Instant, interval, sleep_until};

// long enough to cross Rekey-After-Time (120s) with traffic on both sides
const RUN_TIME: Duration = Duration::from_secs(200);
const PING_INTERVAL: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() {
    let our_private = StaticSecret::from(
        <[u8; 32]>::try_from(
            hex::decode("6a77ff2a229f49372a8920e608ff6a066ad2e2762adfdff77018e61b0c7fe833")
                .unwrap(),
        )
        .unwrap(),
    );
    println!(
        "rust public key (hex): {}",
        hex::encode(PublicKey::from(&our_private).as_bytes())
    );

    let go_public = PublicKey::from(
        <[u8; 32]>::try_from(
            hex::decode("8eba4fe57f66352c6391dead0a71f0751238469f199eab908f7e1402a959a71f")
                .unwrap(),
        )
        .unwrap(),
    );

    let bind: SocketAddr = "127.0.0.1:51820".parse().unwrap();
    let go_addr: SocketAddr = "127.0.0.1:51821".parse().unwrap();

    let tunnel = Tunnel::new(bind, our_private).await.unwrap();
    let mut peer = tunnel.connect_peer(go_public, go_addr).await.unwrap();
    println!("sent handshake init; waiting for handshake to complete");
    peer.ready().await.unwrap();
    println!("handshake complete");

    let started = Instant::now();
    let end = started + RUN_TIME;
    let mut ping = interval(PING_INTERVAL);
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
