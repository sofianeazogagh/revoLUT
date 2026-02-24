use std::time::Instant;

use revolut::{lut::MNLUT, nlwe::NLWE, packed_lut::PackedMNLUT, *};
use tfhe::shortint::parameters::*;

mod matmul;

pub fn bench_blind_lt() {
    let params = [
        PARAM_MESSAGE_1_CARRY_0,
        PARAM_MESSAGE_2_CARRY_0,
        PARAM_MESSAGE_3_CARRY_0,
        PARAM_MESSAGE_4_CARRY_0,
    ];
    for param in params {
        let mut ctx = Context::from(param);
        let private_key = key(ctx.parameters());
        let public_key = &private_key.public_key;
        let p = ctx.full_message_modulus() as u64;
        let n = 24;
        let u = p.pow(n as u32);
        println!("Blind LT benchmarks for p = {p}, n = {n} (up to {u} values)");
        let a = NLWE::from_plain(0, n, &mut ctx, &private_key);
        let b = NLWE::from_plain(1, n, &mut ctx, &private_key);
        let start = Instant::now();
        let lt = a.blind_lt(&b, &ctx, public_key);
        println!("elapsed: {:?}", Instant::now() - start);
    }
}

pub fn main() {
    bench_blind_lt();
}
