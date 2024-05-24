use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use revolut::{key, random_lut, Context};
use tfhe::shortint::parameters::*;

fn bench_bcs(c: &mut Criterion, param: ClassicPBSParameters) {
    let size = param.message_modulus.0;
    let bitsize = size.ilog2() as usize;
    let private_key = key(param);
    c.bench_function(&format!("blind counting sort {} bits", bitsize), |b| {
        b.iter_batched(
            || random_lut(param),
            |lut| {
                private_key
                    .public_key
                    .blind_counting_sort(black_box(lut), &Context::from(param))
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_bcs(c, PARAM_MESSAGE_2_CARRY_0);
    bench_bcs(c, PARAM_MESSAGE_3_CARRY_0);
    bench_bcs(c, PARAM_MESSAGE_4_CARRY_0);
    bench_bcs(c, PARAM_MESSAGE_5_CARRY_0);
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = criterion_benchmark
}
criterion_main!(benches);
