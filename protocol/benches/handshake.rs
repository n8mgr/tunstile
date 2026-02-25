use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use spacetun_protocol::{
    cookies::Generator,
    handshake::Handshake,
    messages::{HandshakeInitMsg, HandshakeResponseMsg},
};
use tai64::Tai64N;
use x25519_dalek::{PublicKey, StaticSecret};

fn bench_handshake(c: &mut Criterion) {
    let sk1 = StaticSecret::random();
    let pk1 = PublicKey::from(&sk1);
    let sk2 = StaticSecret::random();
    let pk2 = PublicKey::from(&sk2);

    let c_init = Generator::new(pk2);
    let c_resp = Generator::new(pk1);

    c.bench_function("handshake_e2e", |b| {
        b.iter_batched(
            || (StaticSecret::random(), StaticSecret::random()),
            |(hs_init, hs_resp)| {
                let mut init_buf = [0u8; HandshakeInitMsg::MESSAGE_LENGTH];
                let h_init = Handshake::new(sk1.clone(), pk2);
                let h_init =
                    h_init.initiate(100, hs_init, Tai64N::UNIX_EPOCH, &c_init, &mut init_buf);

                let init_msg = HandshakeInitMsg::decode(&init_buf);

                let mut resp_buf = [0u8; HandshakeResponseMsg::MESSAGE_LENGTH];
                let h_resp = Handshake::new(sk2.clone(), pk1);
                let h_resp = h_resp.receive(init_msg).respond(
                    200,
                    hs_resp,
                    None,
                    Tai64N::UNIX_EPOCH,
                    &c_resp,
                    &mut resp_buf,
                );

                let resp_msg = HandshakeResponseMsg::decode(&resp_buf);
                let h_init = h_init.response_received(None, resp_msg);

                let _t_init = h_init.finish();
                let _t_resp = h_resp.finish();
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_handshake);
criterion_main!(benches);
