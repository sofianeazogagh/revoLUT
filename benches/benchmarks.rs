use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::Rng;
use revolut::{key2, key3, key4, Context, PrivateKey, LUT};
use tfhe::shortint::parameters::{
    PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_3_CARRY_0, PARAM_MESSAGE_4_CARRY_0,
};

fn random_lut(size: usize, key: &PrivateKey, ctx: &mut Context) -> LUT {
    let mut rng = rand::thread_rng();
    let array: Vec<u64> = (0..4).map(|_| rng.gen_range(0..4)).collect();
    LUT::from_vec(&array, &key, ctx)
}

fn criterion_benchmark(c: &mut Criterion) {
    // c.bench_function("blindsort bma 4", |b| {
    //     b.iter_batched(
    //         || random_lut(4, key2(), &mut Context::from(PARAM_MESSAGE_2_CARRY_0)),
    //         |lut| {
    //             key2()
    //                 .public_key
    //                 .blind_sort_bma(black_box(lut), &Context::from(PARAM_MESSAGE_2_CARRY_0))
    //         },
    //         BatchSize::SmallInput,
    //     )
    // });
    // c.bench_function("blindsort bma 8", |b| {
    //     b.iter_batched(
    //         || random_lut(8, key3(), &mut Context::from(PARAM_MESSAGE_3_CARRY_0)),
    //         |lut| {
    //             key3()
    //                 .public_key
    //                 .blind_sort_bma(black_box(lut), &Context::from(PARAM_MESSAGE_3_CARRY_0))
    //         },
    //         BatchSize::SmallInput,
    //     )
    // });
    // c.bench_function("blindsort 2bp 4", |b| {
    //     b.iter_batched(
    //         || random_lut(4, key2(), &mut Context::from(PARAM_MESSAGE_2_CARRY_0)),
    //         |lut| {
    //             key2()
    //                 .public_key
    //                 .blind_sort_2bp(black_box(lut), &Context::from(PARAM_MESSAGE_2_CARRY_0))
    //         },
    //         BatchSize::SmallInput,
    //     )
    // });
    // c.bench_function("blindsort 2bp 8", |b| {
    //     b.iter_batched(
    //         || random_lut(8, key3(), &mut Context::from(PARAM_MESSAGE_3_CARRY_0)),
    //         |lut| {
    //             key3()
    //                 .public_key
    //                 .blind_sort_2bp(black_box(lut), &Context::from(PARAM_MESSAGE_3_CARRY_0))
    //         },
    //         BatchSize::SmallInput,
    //     )
    // });
    // c.bench_function("blindsort 2bp 16", |b| {
    //     b.iter_batched(
    //         || random_lut(16, key4(), &mut Context::from(PARAM_MESSAGE_4_CARRY_0)),
    //         |lut| {
    //             key4()
    //                 .public_key
    //                 .blind_sort_2bp(black_box(lut), &Context::from(PARAM_MESSAGE_4_CARRY_0))
    //         },
    //         BatchSize::SmallInput,
    //     )
    // });
    c.bench_function("blind permutation", |b| {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let setup = || {
            (
                random_lut(16, key4(), &mut ctx),
                Vec::from_iter((0..16).map(|i| key4().allocate_and_encrypt_lwe(i, &mut ctx))),
            )
        };
        let ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let routine = |(lut, permutation)| {
            key4()
                .public_key
                .blind_permutation(black_box(lut), black_box(permutation), &ctx)
        };
        b.iter_batched(setup, routine, BatchSize::SmallInput)
    });
}

// criterion_group!(benches, criterion_benchmark);
criterion_group! {
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = criterion_benchmark
}
criterion_main!(benches);
