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

use revolut::{Context, PrivateKey,LUT};
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_3_CARRY_0, PARAM_MESSAGE_4_CARRY_0, PARAM_MESSAGE_5_CARRY_0};
use tfhe::shortint::ClientKey;
use tfhe::shortint::ServerKey;



// mod uni_test;
// use uni_test::*;

pub fn main() {

    let param = PARAM_MESSAGE_3_CARRY_0;
    let mut ctx = Context::from(param);

    let cks = ClientKey::new(param);
    let sks = ServerKey::new(&cks);

    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();

    let storage = cks.encrypt(2);
    let lut_new_cell_content = LUT::from_big_lwe(&storage.ct,&public_key,&ctx);
    private_key.debug_glwe("test glwe",&lut_new_cell_content.0,&ctx);


}
