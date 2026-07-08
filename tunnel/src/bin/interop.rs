use etherparse::PacketBuilder;
use spacetun_tunnel::{PublicKey, StaticSecret, Tunnel};
use std::{net::SocketAddr, thread::sleep, time::Duration};

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
    let peer = tunnel.connect_peer(go_public, go_addr).await.unwrap();
    println!("sent handshake init; waiting for handshake to complete");

    sleep(Duration::from_millis(500));

    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(12345, 12345);
    let mut ip_pkt = Vec::new();
    builder.write(&mut ip_pkt, b"hello from rust").unwrap();
    peer.send(ip_pkt).await.unwrap();
    println!("sent transport packet");

    sleep(Duration::from_millis(500));
}
