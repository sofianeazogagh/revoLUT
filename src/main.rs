// #![allow(dead_code)]
// #![allow(unused_variables)]

use revolut::*;
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

pub fn main() {
    generate_keys();
    // let param = PARAM_MESSAGE_4_CARRY_0;
    // let mut ctx = Context::from(param);
    // let private_key = key(param);
    // let public_key = &private_key.public_key;
    // let array = vec![3, 2, 1, 2];
    // let lut = LUT::from_vec(&array, &private_key, &mut ctx);
    // lut.print(&private_key, &ctx);

    // for k in 2..10 {
    //     let now = std::time::Instant::now();
    //     let sorted_lut = public_key.blind_counting_sort_k(&lut, &ctx, k);
    //     println!("{:?}", std::time::Instant::now() - now);
    //     sorted_lut.print(&private_key, &ctx);
    // }
}
