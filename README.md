# SpaceTun

An experimental Rust implementation of the Wireguard spec. For fun and learning. Not for production use.

## Structure

- `protocol` - a Wireguard-compatible protocol implementation. `no_std` compatible.
- `device` - handles tun interface creation, management, UDP sockets, and packet processing.
