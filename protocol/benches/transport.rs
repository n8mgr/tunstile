use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use rand::random;
use spacetun_protocol::{
    cookies::Generator,
    handshake::{Handshake, INIT_MSG_LENGTH, RESP_MSG_LENGTH},
    transport::Transport,
};
use tai64::Tai64N;
use x25519_dalek::{PublicKey, StaticSecret};

fn complete_handshake() -> (Transport, Transport) {
    let sk1 = StaticSecret::random();
    let pk1 = PublicKey::from(&sk1);
    let sk2 = StaticSecret::random();
    let pk2 = PublicKey::from(&sk2);

    let c_init = Generator::new(pk2);
    let c_resp = Generator::new(pk1);

    let mut init_buf = [0u8; INIT_MSG_LENGTH];
    let h_init = Handshake::initiate(
        sk1,
        pk2,
        100,
        StaticSecret::random(),
        Tai64N::UNIX_EPOCH,
        &c_init,
        &mut init_buf,
    );

    let mut resp_buf = [0u8; RESP_MSG_LENGTH];
    let h_resp = Handshake::receive(sk2, &mut init_buf)
        .expect("invalid init message")
        .respond(
            200,
            StaticSecret::random(),
            None,
            Tai64N::UNIX_EPOCH,
            &c_resp,
            &mut resp_buf,
        );

    let h_init = h_init
        .response_received(None, &mut resp_buf)
        .expect("invalid response received");

    (h_init.finish(), h_resp.finish())
}

const PAYLOAD_LEN: usize = 1420;
const WIRE_LEN: usize = Transport::packet_len(PAYLOAD_LEN);

fn bench_transport(c: &mut Criterion) {
    let (mut t_init, mut t_resp) = complete_handshake();

    let mut group = c.benchmark_group("transport");
    group.throughput(Throughput::Bits((PAYLOAD_LEN * 8) as u64));
    group.bench_function("send", |b| {
        let payload = [0xABu8; PAYLOAD_LEN];
        let mut buf = vec![0u8; WIRE_LEN];
        b.iter(|| {
            t_init.send(&payload, &mut buf);
        });
    });

    group.bench_function("receive", |b| {
        b.iter_batched(
            || {
                let payload: [u8; 1420] = random();
                let mut buf = vec![0u8; WIRE_LEN];
                t_init.send(&payload, &mut buf);
                (payload, buf)
            },
            |(payload, mut encrypted_packet)| {
                let received_payload = t_resp.receive(&mut encrypted_packet).unwrap();
                assert_eq!(received_payload, payload);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_transport);
criterion_main!(benches);
