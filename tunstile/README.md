# tunstile

`tunstile` is the complete Tunstile device library and command-line program.
`Device` applies AllowedIPs routing and source validation to IP packets. A
platform integration exchanges packets through `Device::send_packet` and
`Device::recv_packet`.

This is the top layer. Packet-oriented integrations drive those methods
directly; applications that need peer-oriented encrypted payloads without IP
routing can use `tunstile_tunnel` directly.

## Command line

Install the `tunstile` binary:

```sh
cargo install tunstile
```

Run it with a wg-quick-style configuration file:

```sh
tunstile tunnel.conf
```

Creating a TUN interface usually requires elevated privileges. Automatic OS
route installation is currently implemented only on macOS.

## Library

```rust
use std::{error::Error, net::SocketAddr};
use tunstile::{Device, PeerConfig, PrivateKey, PublicKey};

async fn start(
    private_key: PrivateKey,
    peer_key: PublicKey,
    endpoint: SocketAddr,
) -> Result<Device, Box<dyn Error>> {
    let device = Device::new("0.0.0.0:0".parse()?, private_key).await?;
    device
        .add_peer(
            &peer_key,
            PeerConfig {
                endpoint: Some(endpoint),
                allowed_ips: vec!["0.0.0.0/0".parse()?],
                ..Default::default()
            },
        )
        .await?;

    Ok(device)
}
```

Peers remain registered until removed with `Device::remove_peer`. Feed outbound
interface packets into `Device::send_packet` and inject packets returned by
`Device::recv_packet`. `Device::send_packet` applies backpressure;
`Device::try_send_packet` instead drops when the selected peer's queue is full.
Both methods also drop invalid and unroutable packets, returning errors only for
operational failures. Only one `recv_packet` call may be active at a time.
Interface addresses and operating-system routes remain the platform
integration's responsibility.

`Device::set_peer` replaces a registered peer's configuration in place.
AllowedIPs change atomically, and the peer's protocol state remains intact.
An endpoint in the new configuration replaces the current one; omitting it
keeps the current or roamed endpoint.

Android integrations can protect an already-bound UDP socket, pass it to
`Device::from_socket`, and pump the detached VPN descriptor through the packet
methods. Apple packet tunnel providers can bridge packet-flow callbacks to the
same methods.

This implementation is experimental and has not been audited for production
use.
