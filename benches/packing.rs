use criterion::{criterion_group, criterion_main, Criterion};
use revolut::{key, Context};
use tfhe::{
    core_crypto::{
        algorithms::{
            par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext,
            par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext,
        },
        entities::{GlweCiphertext, LweCiphertextList},
    },
    shortint::parameters::*,
};

fn bench_packing(c: &mut Criterion, param: ClassicPBSParameters) {
    let size = param.message_modulus.0;
    let bitsize = size.ilog2() as usize;
    let private_key = key(param);
    let mut ctx = Context::from(param);
    let lwe = private_key.allocate_and_encrypt_lwe(42, &mut ctx);
    let lwe_ciphertext_list = LweCiphertextList::from_container(
        lwe.clone().into_container(),
        ctx.small_lwe_dimension().to_lwe_size(),
        ctx.ciphertext_modulus(),
    );
    let mut glwe = GlweCiphertext::new(
        0,
        ctx.glwe_dimension().to_glwe_size(),
        ctx.polynomial_size(),
        ctx.ciphertext_modulus(),
    );
    c.bench_function(&format!("packing lwe {} bits", bitsize), |b| {
        b.iter(|| {
            par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                &private_key.public_key.pfpksk,
                &mut glwe,
                &lwe,
            )
        })
    });
    c.bench_function(&format!("packing lwe list {} bits", bitsize), |b| {
        b.iter(|| {
            par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                &private_key.public_key.pfpksk,
                &mut glwe,
                &lwe_ciphertext_list,
            )
        })
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_packing(c, PARAM_MESSAGE_2_CARRY_0);
    bench_packing(c, PARAM_MESSAGE_3_CARRY_0);
    bench_packing(c, PARAM_MESSAGE_4_CARRY_0);
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = criterion_benchmark
}
criterion_main!(benches);
