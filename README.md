# Tunstile

An experimental Rust implementation of the Wireguard spec focusing on programmability

## Structure

- `tunstile` - packet routing, AllowedIPs enforcement, a platform packet boundary, and the command-line program.
- `tunnel` - a self-maintaining Wireguard tunnel: UDP sockets, sessions, timers, and packet processing.
- `protocol` - a Wireguard-compatible protocol implementation. `no_std` compatible.

## Benchmarks

`cargo bench`, 1420-byte payloads.

### Apple M4 Max
```
handshake_e2e       205.77 µs
transport/send      729.02 ns   15.58 Gb/s
transport/receive   913.00 ns   12.44 Gb/s
```
