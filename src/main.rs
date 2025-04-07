// #![allow(dead_code)]
// #![allow(unused_variables)]

use std::time::Instant;

use revolut::{
    lut::{MNLUT, NLWE},
    *,
};
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
    let mut ctx = Context::from(PARAM_MESSAGE_5_CARRY_0);
    let private_key = key(ctx.parameters());
    let p = ctx.full_message_modulus() as u64;
    // 64k values
    // let data = Vec::from_iter(0..p.pow(4));
    // 1M values
    let data = Vec::from_iter(0..p.pow(5));

    println!("Blind Read benchmarks for p = {p}");
    for m in 1..=4 {
        let n = 1;
        // for n in 1..=4 {
        print!(
            "M = {m}, N = {n} (up to {} values mod {}): ",
            p.pow(m as u32),
            p.pow(n as u32)
        );
        let lut = MNLUT::from_plain(&data, m, n, &private_key, &mut ctx);
        let index = NLWE::from_plain(0, m, &mut ctx, &private_key);
        let value = NLWE::from_plain(0, n, &mut ctx, &private_key);
        let start = Instant::now();
        // let nlwe = lut.blind_tensor_access(&index, &ctx, &private_key.public_key);
        MNLUT::blind_tensor_lift(&index, &value, &ctx, &private_key.public_key);
        let elapsed = Instant::now() - start;
        println!("{:?}", elapsed);
        // assert_eq!(nlwe.to_plain(&ctx, &private_key), 0);
        // }
    }
}

pub fn main() {
    // generate_keys();
    // bench_blind_read();
    let param = PARAM_MESSAGE_4_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = key(param);
    for i in 0..=ctx.full_message_modulus().ilog2() {
        println!("packing {} lwe into a lut", 2usize.pow(i));
        let lwe = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
        let start = Instant::now();
        let lut = LUT::from_vec_of_lwe(&vec![lwe; 2usize.pow(i)], public_key, &ctx);
        println!("==> elapsed {:?}", Instant::now() - start);
    }

    // for k in 2..10 {
    //     let now = std::time::Instant::now();
    //     let sorted_lut = public_key.blind_counting_sort_k(&lut, &ctx, k);
    //     println!("{:?}", std::time::Instant::now() - now);
    //     sorted_lut.print(&private_key, &ctx);
    // }
    //
}
