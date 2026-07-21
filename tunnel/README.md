# tunstile_tunnel

`tunstile_tunnel` drives `tunstile_protocol` over a UDP socket. It owns peer
sessions, handshake retries, keepalives, endpoint roaming, and receiver-index
routing.

This is the middle layer in Tunstile. It sends and receives payloads for named
peers but does not create a TUN interface, inspect IP packets, or apply
AllowedIPs policy. The `tunstile` crate handles those responsibilities.

## Usage

```toml
[dependencies]
tunstile_tunnel = "0.0.1"
```

```rust
use std::{error::Error, net::SocketAddr};
use tunstile_tunnel::{Peer, PeerConfig, PrivateKey, PublicKey, Tunnel};

async fn connect(
    private_key: PrivateKey,
    peer_key: PublicKey,
    endpoint: SocketAddr,
) -> Result<(Tunnel, Peer), Box<dyn Error>> {
    let bind_addr = "0.0.0.0:0".parse()?;
    let tunnel = Tunnel::new(bind_addr, private_key).await?;
    let peer = tunnel
        .add_peer(PeerConfig::new(peer_key).endpoint(endpoint))
        .await?;

    Ok((tunnel, peer))
}
```

Use `Peer::send` and `Peer::recv` for payloads. Dropping a `Peer` unregisters
it. `Tunnel::from_socket` accepts an already-bound socket when the caller must
configure it first, such as protecting an Android VPN socket.

This implementation is experimental and has not been audited for production
use.
