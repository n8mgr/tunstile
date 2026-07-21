# tunstile

`tunstile` is the complete Tunstile device library and command-line program. It
combines a TUN interface, AllowedIPs routing and source validation, and the UDP
tunnel provided by `tunstile_tunnel`.

This is the top layer. Applications that already own their packet interface can
use `Device::from_fd`; applications that need peer-oriented encrypted payloads
without IP routing can use `tunstile_tunnel` directly.

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
use tunstile::{Device, DeviceConfig, DevicePeer, PeerConfig, PrivateKey, PublicKey};

async fn start(
    private_key: PrivateKey,
    peer_key: PublicKey,
    endpoint: SocketAddr,
) -> Result<(Device, DevicePeer), Box<dyn Error>> {
    let device = Device::new(DeviceConfig::new(private_key, "10.0.0.2/32".parse()?)).await?;
    let peer = device
        .add_peer(
            PeerConfig::new(peer_key)
                .endpoint(endpoint)
                .allowed_ip("0.0.0.0/0".parse()?),
        )
        .await?;

    Ok((device, peer))
}
```

Keep each returned `DevicePeer` alive for as long as the peer should remain
registered. Installing matching routes in the operating system is the caller's
responsibility when using the library.

This implementation is experimental and has not been audited for production
use.
