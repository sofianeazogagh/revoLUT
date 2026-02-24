use std::time::{Duration, Instant};

use revolut::{nlwe::NLWE, *};
use tfhe::shortint::parameters::*;

use rand::prelude::*;

mod matmul;

pub fn bench_blind_lt() {
    let mut rng = rand::thread_rng();
    let params = [
        // PARAM_MESSAGE_1_CARRY_0,
        // PARAM_MESSAGE_2_CARRY_0,
        // PARAM_MESSAGE_3_CARRY_0,
        PARAM_MESSAGE_4_CARRY_0,
    ];
    for param in params {
        let mut ctx = Context::from(param);
        let private_key = key(ctx.parameters());
        let public_key = &private_key.public_key;
        let p = ctx.full_message_modulus() as u64;
        let digits = 8usize;
        for n in 1..=digits {
            let u = p.pow(n as u32);
            let bits = p.ilog2() * n as u32;
            println!("Blind LT benchmarks for p = {p}, n = {n} ({bits} bits values)");
            let number_of_runs = 10;
            let mut total_time = Duration::ZERO;
            for _ in 0..number_of_runs {
                let a_val = rng.gen_range(0..u);
                let b_val = rng.gen_range(0..u);
                let a = NLWE::from_plain(a_val, n, &mut ctx, &private_key);
                let b = NLWE::from_plain(b_val, n, &mut ctx, &private_key);
                let start = Instant::now();
                let lt = a.blind_lt(&b, &ctx, public_key);
                total_time += Instant::now() - start ;
                assert_eq!(private_key.decrypt_lwe(&lt, &ctx), (a_val < b_val) as u64);
            }
            println!("Average time: {:.2?}", total_time / number_of_runs);
        }

    }
}

pub fn main() {
    bench_blind_lt();
}
