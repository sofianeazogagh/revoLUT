// #![allow(dead_code)]
// #![allow(unused_variables)]

use std::fs;

use revolut::*;
use tfhe::shortint::parameters::*;

// mod uni_test;
// use uni_test::*;

pub fn generate_keys() {
    println!("generating keys and saving them to disk");
    let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx); // this takes time
    let _ = fs::write("PrivateKey2", &bincode::serialize(&private_key).unwrap());
    let mut ctx = Context::from(PARAM_MESSAGE_3_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx); // this takes time
    let _ = fs::write("PrivateKey3", &bincode::serialize(&private_key).unwrap());
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx); // this takes time
    let _ = fs::write("PrivateKey4", &bincode::serialize(&private_key).unwrap());
    let mut ctx = Context::from(PARAM_MESSAGE_5_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx); // this takes time
    let _ = fs::write("PrivateKey5", &bincode::serialize(&private_key).unwrap());
}

pub fn main() {
    // generate_keys();
    let param = PARAM_MESSAGE_4_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = key(param);
    let public_key = &private_key.public_key;
    let array = vec![3, 2, 1, 2];
    let lut = LUT::from_vec(&array, &private_key, &mut ctx);
    let permutation = (0..16)
        .map(|i| private_key.allocate_and_encrypt_lwe(i, &mut ctx))
        .collect();

    let now = std::time::Instant::now();
    // let sorted_lut = public_key.blind_counting_sort(lut, &ctx);
    // let _ = public_key.blind_sort_2bp(lut, &ctx);
    let _ = public_key.blind_permutation(lut, permutation, &ctx);
    println!("{:?}", std::time::Instant::now() - now);

    // test_blind_tensor_access();

    // test_blind_permutation();
    // blind_array_access(); // from blind_array_access

    // blind_array_access2d(); // from unitest_bacc2d

    // blind_permutation(); // from blind_permutation

    // blind_insertion(); // from blind_insertion

    // blind_retrieve(); // from blind_retrieve

    // blind_push(); // from blind_push

    // blind_pop(); // from blind_pop

    // private_insert(); // from private_insert

    // test_perf_comp();

    // test_comp_with_bmacc();

    // test_perf_blind_rotation();

    // test_perf_extract_switch();

    // test_perf_packing();

    // test_perf_glwe_sum();

    // test_perf_lwe_sum();

    // gist::packing_test();
}
