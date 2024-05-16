use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use revolut::{key, random_lut, Context};
use tfhe::shortint::parameters::*;

fn bench_2bp(c: &mut Criterion, param: ClassicPBSParameters) {
    let bitsize = param.message_modulus.0.ilog2() as usize;
    c.bench_function(&format!("blindsort 2bp {}", bitsize), |b| {
        b.iter_batched(
            || random_lut(param),
            |lut| {
                key(param)
                    .public_key
                    .blind_sort_2bp(black_box(lut), &Context::from(param))
            },
            BatchSize::SmallInput,
        )
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_2bp(c, PARAM_MESSAGE_2_CARRY_0);
    bench_2bp(c, PARAM_MESSAGE_3_CARRY_0);
    bench_2bp(c, PARAM_MESSAGE_4_CARRY_0);
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = criterion_benchmark
}
criterion_main!(benches);
