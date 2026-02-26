use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use spacetun_protocol::{
    cookies::Generator,
    handshake::Handshake,
    messages::{HandshakeInitMsg, HandshakeResponseMsg, TransportDataMsg},
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

    let mut init_buf = [0u8; HandshakeInitMsg::MESSAGE_LENGTH];
    let h_init = Handshake::new(sk1, pk2);
    let h_init = h_init.initiate(
        100,
        StaticSecret::random(),
        Tai64N::UNIX_EPOCH,
        &c_init,
        &mut init_buf,
    );

    let init_msg = HandshakeInitMsg::decode(&init_buf);

    let mut resp_buf = [0u8; HandshakeResponseMsg::MESSAGE_LENGTH];
    let h_resp = Handshake::new(sk2, pk1);
    let h_resp = h_resp.receive(init_msg).respond(
        200,
        StaticSecret::random(),
        None,
        Tai64N::UNIX_EPOCH,
        &c_resp,
        &mut resp_buf,
    );

    let resp_msg = HandshakeResponseMsg::decode(&resp_buf);
    let h_init = h_init.response_received(None, resp_msg);

    (h_init.finish(), h_resp.finish())
}

const PAYLOAD_LEN: usize = 1400;

fn bench_transport_send(c: &mut Criterion) {
    let wire_len = TransportDataMsg::encoded_len(PAYLOAD_LEN);
    let (mut t_init, _t_resp) = complete_handshake();

    c.bench_function("transport_send_1400b", |b| {
        let payload = [0xABu8; PAYLOAD_LEN];
        let mut buf = vec![0u8; wire_len];
        b.iter(|| {
            t_init.send(&payload, &mut buf);
        });
    });
}

fn bench_transport_receive(c: &mut Criterion) {
    let wire_len = TransportDataMsg::encoded_len(PAYLOAD_LEN);
    let (mut t_init, mut t_resp) = complete_handshake();

    c.bench_function("transport_receive_1400b", |b| {
        b.iter_batched(
            || {
                let payload = [0xABu8; PAYLOAD_LEN];
                let mut buf = vec![0u8; wire_len];
                t_init.send(&payload, &mut buf);
                buf
            },
            |mut buf| {
                let msg = TransportDataMsg::decode(&mut buf);
                let _ = t_resp.receive(msg).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_transport_send, bench_transport_receive);
criterion_main!(benches);
