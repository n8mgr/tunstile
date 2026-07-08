use std::{net::SocketAddr, sync::Arc, thread::sleep, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use spacetun_device::{PublicKey, StaticSecret, Tunnel};
use tokio::{runtime::Runtime, sync::Mutex, sync::mpsc::Receiver};

const PAYLOAD_LEN: usize = 1420;
const BATCH: usize = 256;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

type Established = (
    Arc<Tunnel>,
    Tunnel,
    Arc<Mutex<Receiver<Vec<u8>>>>,
    PublicKey,
);

fn setup(rt: &Runtime) -> Established {
    let _ = env_logger::try_init();
    rt.block_on(async {
        let sk_a = StaticSecret::random();
        let pk_a = PublicKey::from(&sk_a);
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);

        let (tunnel_a, _rx_a) = Tunnel::new(loopback(), sk_a).await.unwrap();
        let (tunnel_b, rx_b) = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        tunnel_b.allow_peer(pk_a);
        tunnel_a.connect_peer(pk_b, addr_b).await;

        loop {
            if let Some(ps) = tunnel_a.peer(&pk_b)
                && ps.last_successful_handshake.is_some()
            {
                break;
            }
            sleep(Duration::from_millis(50));
        }

        (
            Arc::new(tunnel_a),
            tunnel_b,
            Arc::new(Mutex::new(rx_b)),
            pk_b,
        )
    })
}

fn bench_roundtrip(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (tunnel_a, _tunnel_b, rx_b, pk_b) = setup(&rt);
    let payload = vec![0xABu8; PAYLOAD_LEN];

    let mut group = c.benchmark_group("tunnel");
    group.throughput(Throughput::Bits(PAYLOAD_LEN as u64 * 8));
    group.bench_function("datapath_roundtrip", |b| {
        b.to_async(&rt).iter(|| {
            let tunnel_a = tunnel_a.clone();
            let rx_b = rx_b.clone();
            let payload = payload.clone();
            async move {
                tunnel_a.send(pk_b, payload).await;
                rx_b.lock().await.recv().await.unwrap();
            }
        });
    });
    group.finish();
}

fn bench_pipelined(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (tunnel_a, _tunnel_b, rx_b, pk_b) = setup(&rt);
    let payload = vec![0xABu8; PAYLOAD_LEN];

    let mut group = c.benchmark_group("tunnel");
    group.throughput(Throughput::Bits((BATCH * PAYLOAD_LEN) as u64 * 8));
    group.bench_function("datapath_pipelined", |b| {
        b.to_async(&rt).iter(|| {
            let tunnel_a = tunnel_a.clone();
            let rx_b = rx_b.clone();
            let payload = payload.clone();
            async move {
                let send_all = async {
                    for _ in 0..BATCH {
                        tunnel_a.send(pk_b, payload.clone()).await;
                    }
                };
                let recv_all = async {
                    let mut rx = rx_b.lock().await;
                    for _ in 0..BATCH {
                        rx.recv().await.unwrap();
                    }
                };
                tokio::join!(send_all, recv_all);
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_roundtrip, bench_pipelined);
criterion_main!(benches);
