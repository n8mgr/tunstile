# tunstile_protocol

`tunstile_protocol` implements the WireGuard handshake, transport, cookie, and
per-peer state machines. It is `no_std` by default and does not create sockets,
spawn tasks, read clocks, or allocate packet buffers.

This is the lowest layer in Tunstile. `tunstile_tunnel` supplies the runtime,
scheduling, and UDP transport, while `tunstile` adds IP routing and a TUN
interface.

## Usage

Use this crate when integrating the protocol with a custom runtime or network
stack:

```toml
[dependencies]
tunstile_protocol = "0.0.1"
```

```rust
use tunstile_protocol::{PrivateKey, PublicKey, peer::Peer};

fn new_peer(private_key: PrivateKey, public_key: PublicKey) -> Peer {
    Peer::new(private_key, public_key)
}
```

The caller supplies time, randomness, session indices, packet buffers, and the
handshake and keepalive schedule. Enable the `std` feature for key generation
and standard-library integrations.

This implementation is experimental and has not been audited for production
use.
