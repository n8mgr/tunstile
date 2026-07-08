# SpaceTun

An experimental Rust implementation of the Wireguard spec. For fun and learning. Not for production use.

## Structure

- `protocol` - a Wireguard-compatible protocol implementation. `no_std` compatible.
- `tunnel` - a self-maintaining Wireguard tunnel: UDP sockets, sessions, timers, and packet processing.

## Benchmarks

### Apple M4 Max
```
Running benches/handshake.rs (target/release/deps/handshake-2433205187185ddf)
Gnuplot not found, using plotters backend
handshake_e2e           time:   [205.42 µs 205.77 µs 206.16 µs]
                   change: [−0.2217% +0.1026% +0.4706%] (p = 0.56 > 0.05)
                   No change in performance detected.
Found 4 outliers among 100 measurements (4.00%)
1 (1.00%) low severe
1 (1.00%) low mild
2 (2.00%) high severe

Running benches/transport.rs (target/release/deps/transport-51b044a2d9c966a1)
Gnuplot not found, using plotters backend
transport/send          time:   [728.34 ns 729.02 ns 729.80 ns]
                   thrpt:  [15.566 Gb/s 15.582 Gb/s 15.597 Gb/s]
            change:
                   time:   [−1.5743% −1.2132% −0.8672%] (p = 0.00 < 0.05)
                   thrpt:  [+0.8748% +1.2281% +1.5995%]
                   Change within noise threshold.
Found 12 outliers among 100 measurements (12.00%)
6 (6.00%) high mild
6 (6.00%) high severe
transport/receive       time:   [910.94 ns 913.00 ns 915.03 ns]
                   thrpt:  [12.415 Gb/s 12.443 Gb/s 12.471 Gb/s]
            change:
                   time:   [+0.9434% +1.3308% +1.6981%] (p = 0.00 < 0.05)
                   thrpt:  [−1.6697% −1.3134% −0.9345%]
                   Change within noise threshold.
Found 6 outliers among 100 measurements (6.00%)
1 (1.00%) low mild
5 (5.00%) high mild
```
