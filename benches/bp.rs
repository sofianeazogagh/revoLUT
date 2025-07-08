use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use revolut::{key, random_lut, Context};
use tfhe::shortint::parameters::*;

fn bench_bp(c: &mut Criterion, param: ClassicPBSParameters) {
    let size = param.message_modulus.0;
    let bitsize = param.message_modulus.0.ilog2() as usize;
    let private_key = key(param);
    c.bench_function(&format!("blind permutation {}", bitsize), |b| {
        b.iter_batched(
            || {
                let mut ctx = Context::from(param);
                (
                    random_lut(param),
                    Vec::from_iter(
                        (0..size).map(|i| private_key.allocate_and_encrypt_lwe(i as u64, &mut ctx)),
                    ),
                    ctx,
                )
            },
            |(lut, permutation, ctx)| {
                private_key.public_key.blind_permutation(
                    black_box(&lut),
                    black_box(&permutation),
                    &ctx,
                )
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_bp(c, PARAM_MESSAGE_2_CARRY_0);
    bench_bp(c, PARAM_MESSAGE_3_CARRY_0);
    bench_bp(c, PARAM_MESSAGE_4_CARRY_0);
    bench_bp(c, PARAM_MESSAGE_5_CARRY_0);
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = criterion_benchmark
}
criterion_main!(benches);
