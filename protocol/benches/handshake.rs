use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use spacetun_protocol::{
    cookies::Generator,
    handshake::{Handshake, INIT_MSG_LENGTH, RESP_MSG_LENGTH},
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
                let mut init_buf = [0u8; INIT_MSG_LENGTH];
                let h_init = Handshake::initiate(
                    sk1.clone(),
                    pk2,
                    100,
                    hs_init,
                    Tai64N::UNIX_EPOCH,
                    &c_init,
                    &mut init_buf,
                );

                let mut resp_buf = [0u8; RESP_MSG_LENGTH];
                let h_resp = Handshake::receive(sk2.clone(), &mut init_buf)
                    .expect("receive failed")
                    .respond(
                        200,
                        hs_resp,
                        None,
                        Tai64N::UNIX_EPOCH,
                        &c_resp,
                        &mut resp_buf,
                    );

                let h_init = h_init
                    .response_received(None, &mut resp_buf)
                    .expect("response_received failed");

                let _t_init = h_init.finish();
                let _t_resp = h_resp.finish();
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_handshake);
criterion_main!(benches);
