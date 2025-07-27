// #![allow(dead_code)]
// #![allow(unused_variables)]

use std::time::Instant;

use revolut::{lut::MNLUT, nlwe::NLWE, packed_lut::PackedMNLUT, *};
use tfhe::shortint::parameters::*;

// mod uni_test;
// use uni_test::*;

// mod performance_test;
// use performance_test::*;

pub fn generate_keys() {
    println!("generating keys and saving them to disk");
    let params = [
        // PARAM_MESSAGE_2_CARRY_0,
        // PARAM_MESSAGE_3_CARRY_0,
        // PARAM_MESSAGE_4_CARRY_0,
        // PARAM_MESSAGE_5_CARRY_0,
        // PARAM_MESSAGE_6_CARRY_0,
        PARAM_MESSAGE_7_CARRY_0,
        // PARAM_MESSAGE_8_CARRY_0,
    ];
    for param in params {
        crate::key(param);
        println!("=============");
    }
}

pub fn bench_blind_read() {
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = key(ctx.parameters());
    let public_key = &private_key.public_key;
    let p = ctx.full_message_modulus() as u64;
    // 64k values
    // let data = Vec::from_iter(0..p.pow(4));
    // 1M values
    let data = Vec::from_iter(0..p.pow(5));

    println!("Blind Read benchmarks for p = {p}");
    for m in 3..=3 {
        let n = 2;
        // for n in 1..=4 {
        let lut = MNLUT::from_plain(&data, m, n, &private_key, &mut ctx);
        let start = Instant::now();
        let mut lut = PackedMNLUT::from_mnlut(&lut, &ctx, &private_key.public_key);
        println!("PackedMNLUT created in {:?}", Instant::now() - start);
        print!(
            "M = {m}, N = {n} (up to {} values mod {}): ",
            p.pow(m as u32),
            p.pow(n as u32)
        );
        let index = NLWE::from_plain(0, m, &mut ctx, &private_key);
        let value = NLWE::from_plain(0, n, &mut ctx, &private_key);
        let start = Instant::now();
        // MNLUT::blind_tensor_lift(&index, &value, &ctx, &private_key.public_key);
        // let nlwe = lut.blind_tensor_access(&index, &ctx, &private_key.public_key);
        lut.blind_tensor_update(&index, |_| value.clone(), &ctx, public_key);
        // lut.blind_tensor_add_digitwise_overflow(&index, &value, &ctx, &public_key);
        let elapsed = Instant::now() - start;
        println!("{:?}", elapsed);
        // assert_eq!(nlwe.to_plain(&ctx, &private_key), 0);
        // }
    }
}

pub fn main() {
    // let mut ctx = Context::from(PARAM_MESSAGE_7_CARRY_0);

    // let start = Instant::now();
    // let private_key = key(ctx.parameters());
    // println!("Private key generated in {:?}", Instant::now() - start);
    // let public_key = &private_key.public_key;
    // let p = ctx.full_message_modulus() as u64;
    // // let mut lut = LUT::from_function(|x| x, &ctx);
    // let i = private_key.allocate_and_encrypt_lwe(5, &mut ctx);
    // // let lut = LUT::from_lwe(&i, public_key, &ctx);

    // for _ in 0..10 {
    //     let start = Instant::now();
    //     // public_key.blind_rotation(&i, &lut, &ctx);
    //     let lut = LUT::from_lwe(&i, public_key, &ctx);

    //     println!("elapsed: {:?}", Instant::now() - start);
    // }

    // // let data = Vec::from_iter((0..p).map(|_| Vec::from_iter(0..p)));
    // let data = Vec::from_iter((0..p).map(|i| Vec::from_iter((0..p).map(|j| 1))));

    // for l in 0..5 {
    //     let line = private_key.allocate_and_encrypt_lwe(l, &mut ctx);
    //     for c in 0..5 {
    //         let column = private_key.allocate_and_encrypt_lwe(c, &mut ctx);
    //         let start = Instant::now();
    //         let ciphertext = public_key.blind_matrix_access_clear(&data, &line, &column, &ctx);
    //         println!("elapsed: {:?}", Instant::now() - start);
    //         let actual = private_key.decrypt_lwe(&ciphertext, &ctx);
    //         let expected = data[l as usize][c as usize];

    //         println!("({l}, {c}): {actual} vs {expected}");
    //         assert_eq!(actual, expected);
    //     }
    // }

    // generate_keys();
    bench_blind_read();
    // let param = PARAM_MESSAGE_4_CARRY_0;
    // let mut ctx = Context::from(param);
    // let private_key = key(param);
    // let public_key = &private_key.public_key;
    // for i in 0..=ctx.full_message_modulus().ilog2() {
    //     println!("packing {} lwe into a lut", 2usize.pow(i));
    //     let lwe = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
    //     let start = Instant::now();
    //     let lut = LUT::from_vec_of_lwe(&vec![lwe; 2usize.pow(i)], public_key, &ctx);
    //     println!("==> elapsed {:?}", Instant::now() - start);
    // }

    // for k in 2..10 {
    //     let now = std::time::Instant::now();
    //     let sorted_lut = public_key.blind_counting_sort_k(&lut, &ctx, k);
    //     println!("{:?}", std::time::Instant::now() - now);
    //     sorted_lut.print(&private_key, &ctx);
    // }
    //
}
