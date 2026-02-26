use etherparse::PacketBuilder;
use spacetun_protocol::{
    PublicKey, StaticSecret, Tai64N,
    cookies::Generator,
    handshake::Handshake,
    messages::{HandshakeInitMsg, HandshakeResponseMsg, TransportDataMsg},
};
use std::net::UdpSocket;

fn main() {
    let rust_private_bytes =
        hex::decode("6a77ff2a229f49372a8920e608ff6a066ad2e2762adfdff77018e61b0c7fe833").unwrap();
    let our_private = StaticSecret::from(<[u8; 32]>::try_from(rust_private_bytes).unwrap());
    let our_public = PublicKey::from(&our_private);
    println!(
        "rust public key (hex): {}",
        hex::encode(our_public.as_bytes())
    );

    // Go peer's public key — paste the hex from `wg pubkey` here
    let go_public_bytes =
        hex::decode("8eba4fe57f66352c6391dead0a71f0751238469f199eab908f7e1402a959a71f").unwrap();
    let go_public = PublicKey::from(<[u8; 32]>::try_from(go_public_bytes).unwrap());

    let socket = UdpSocket::bind("127.0.0.1:51820").unwrap();
    let go_addr = "127.0.0.1:51821";

    // Send handshake init
    let cookies = Generator::new(go_public);
    let handshake = Handshake::new(our_private, go_public);
    let ephemeral = StaticSecret::random();
    let mut buf = [0u8; HandshakeInitMsg::MESSAGE_LENGTH];
    let handshake = handshake.initiate(1, ephemeral, Tai64N::now(), &cookies, &mut buf);
    println!("handshake init: {}", hex::encode(buf));
    socket.send_to(&buf, go_addr).unwrap();
    println!("sent handshake init ({} bytes)", buf.len());

    // Receive handshake response
    let mut resp_buf = [0u8; HandshakeResponseMsg::MESSAGE_LENGTH];
    socket.recv_from(&mut resp_buf).unwrap();
    println!("received handshake response ({} bytes)", resp_buf.len());
    let resp = HandshakeResponseMsg::decode(&resp_buf);

    // Complete handshake
    let mut transport = handshake.response_received(None, resp).finish();
    println!("handshake complete");

    // Send a transport packet
    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(12345, 12345);

    let mut ip_pkt = Vec::new();
    builder.write(&mut ip_pkt, b"hello from rust").unwrap();

    let mut transport_buf = vec![0u8; TransportDataMsg::encoded_len(ip_pkt.len())];
    transport.send(&ip_pkt, &mut transport_buf);
    socket.send_to(&transport_buf, go_addr).unwrap();
    println!("sent transport packet ({} bytes)", transport_buf.len());
}
