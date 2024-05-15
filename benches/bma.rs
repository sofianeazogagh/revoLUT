use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use revolut::{key, Context, random_lut};
use tfhe::shortint::parameters::*;

fn bench_bma(c: &mut Criterion, param: ClassicPBSParameters) {
    let bitsize = param.message_modulus.0.ilog2() as usize;
    c.bench_function(&format!("blindsort bma {}", bitsize), |b| {
        b.iter_batched(
            || random_lut(param),
            |lut| {
                key(param)
                    .public_key
                    .blind_sort_bma(black_box(lut), &Context::from(param))
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_bma(c, PARAM_MESSAGE_2_CARRY_0);
    bench_bma(c, PARAM_MESSAGE_3_CARRY_0);
    bench_bma(c, PARAM_MESSAGE_4_CARRY_0);
}

// criterion_group!(benches, criterion_benchmark);
criterion_group! {
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = criterion_benchmark
}
criterion_main!(benches);
