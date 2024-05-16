// #![allow(dead_code)]
// #![allow(unused_variables)]

// mod blind_array_access;

// mod blind_array_access2d;

// mod blind_permutation;

// mod blind_insertion;

// mod blind_push;

// mod blind_pop;

// mod blind_retrieve;

// mod private_insert;
// use crate::private_insert::private_insert;

// mod test_perf_basic_op;
// use crate::test_perf_basic_op::*;

// mod uni_test;

// mod blind_sort;
// use crate::blind_sort::*;

// mod blind_tensor_access;
// use blind_tensor_access::*;

// mod demultiplexer;
// use crate::demultiplexer::demultiplixer;

// mod gist;
// use crate::gist::*;

// mod headers;

use std::fs;

use revolut::{Context, PrivateKey};
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_3_CARRY_0, PARAM_MESSAGE_4_CARRY_0, PARAM_MESSAGE_5_CARRY_0};

// mod uni_test;
// use uni_test::*;

pub fn main() {
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
