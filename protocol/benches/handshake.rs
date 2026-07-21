use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use tai64::Tai64N;
use tunstile_protocol::PrivateKey;
use tunstile_protocol::{
    cookies::Generator,
    handshake::{Handshake, INIT_MSG_LENGTH, RESP_MSG_LENGTH},
};
use x25519_dalek::ReusableSecret;

fn bench_handshake(c: &mut Criterion) {
    let sk1 = PrivateKey::from(rand::random::<[u8; 32]>());
    let pk1 = sk1.public_key();
    let sk2 = PrivateKey::from(rand::random::<[u8; 32]>());
    let pk2 = sk2.public_key();

    let mut c_init = Generator::new(&pk2);
    let mut c_resp = Generator::new(&pk1);

    c.bench_function("handshake_e2e", |b| {
        b.iter_batched(
            || (ReusableSecret::random(), ReusableSecret::random()),
            |(hs_init, hs_resp)| {
                let mut init_buf = [0u8; INIT_MSG_LENGTH];
                let h_init = Handshake::initiate(
                    &sk1,
                    &pk2,
                    100,
                    hs_init,
                    Tai64N::UNIX_EPOCH,
                    &mut c_init,
                    &mut init_buf,
                )
                .unwrap();

                let mut resp_buf = [0u8; RESP_MSG_LENGTH];
                let h_resp = Handshake::receive(&sk2, &mut init_buf)
                    .expect("receive failed")
                    .respond(
                        200,
                        hs_resp,
                        None,
                        Tai64N::UNIX_EPOCH,
                        &mut c_resp,
                        &mut resp_buf,
                    )
                    .unwrap();

                let h_init = h_init
                    .response_received(&sk1, None, &mut resp_buf)
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
