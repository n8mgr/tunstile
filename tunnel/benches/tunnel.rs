use std::{net::SocketAddr, sync::Arc};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use tokio::{runtime::Runtime, sync::Mutex};
use tunstile_tunnel::{Peer, PeerConfig, PrivateKey, Tunnel};

const PAYLOAD_LEN: usize = 1420;
const BATCH: usize = 256;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

// the tunnels keep their read loops alive; the peer handles keep the
// registrations alive
type Established = (Tunnel, Arc<Mutex<Tunnel>>, Arc<Peer>, Peer);

fn setup(rt: &Runtime) -> Established {
    let _ = env_logger::try_init();
    rt.block_on(async {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let peer_a = tunnel_b
            .add_peer(&pk_a, PeerConfig::default())
            .await
            .unwrap();
        let peer_b = tunnel_a
            .add_peer(
                &pk_b,
                PeerConfig {
                    endpoint: Some(addr_b),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        peer_b.ready().await.unwrap();

        (
            tunnel_a,
            Arc::new(Mutex::new(tunnel_b)),
            Arc::new(peer_b),
            peer_a,
        )
    })
}

// Latency-bound: reports per-packet round-trip cost, not throughput.
fn bench_roundtrip(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (_tunnel_a, tunnel_b, peer_b, _peer_a) = setup(&rt);
    let payload = vec![0xABu8; PAYLOAD_LEN];

    let mut group = c.benchmark_group("tunnel");
    group.throughput(Throughput::Bits(PAYLOAD_LEN as u64 * 8));
    group.bench_function("datapath_roundtrip", |b| {
        b.to_async(&rt).iter_batched(
            || payload.clone(),
            |payload| {
                let peer_b = peer_b.clone();
                let tunnel_b = tunnel_b.clone();
                async move {
                    peer_b.send(payload).await.unwrap();
                    tunnel_b.lock().await.recv().await;
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

// Bounded mailboxes backpressure the send side and the inbound queue is
// deeper than BATCH, keeping this lossless; reports saturated throughput.
fn bench_pipelined(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (_tunnel_a, tunnel_b, peer_b, _peer_a) = setup(&rt);
    let payload = vec![0xABu8; PAYLOAD_LEN];

    let mut group = c.benchmark_group("tunnel");
    group.throughput(Throughput::Bits((BATCH * PAYLOAD_LEN) as u64 * 8));
    group.bench_function("datapath_pipelined", |b| {
        b.to_async(&rt).iter_batched(
            || vec![payload.clone(); BATCH],
            |payloads| {
                let peer_b = peer_b.clone();
                let tunnel_b = tunnel_b.clone();
                async move {
                    let send_all = async {
                        for payload in payloads {
                            peer_b.send(payload).await.unwrap();
                        }
                    };
                    let recv_all = async {
                        let mut rx = tunnel_b.lock().await;
                        for _ in 0..BATCH {
                            rx.recv().await;
                        }
                    };
                    tokio::join!(send_all, recv_all);
                }
            },
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_roundtrip, bench_pipelined);
criterion_main!(benches);
