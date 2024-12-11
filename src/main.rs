// #![allow(dead_code)]
// #![allow(unused_variables)]

use revolut::*;
use tfhe::{core_crypto::prelude::LweCiphertext, shortint::parameters::*};

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
        // PARAM_MESSAGE_7_CARRY_0,
        // PARAM_MESSAGE_8_CARRY_0,
    ];
    for param in params {
        crate::key(param);
        println!("=============");
    }
}

pub fn main() {
    generate_keys();
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = revolut::key(ctx.parameters());
    let public_key = private_key.get_public_key();

    let cleartext_vec = [1, 2, 4, 3];
    let mut ciphertext_vec :Vec<LweCiphertext<Vec<u64>>> = Vec::new();

    // encrypt the cleartext_vec
    cleartext_vec.iter().for_each(|&x| {
        let ciphertext = private_key.allocate_and_encrypt_lwe(x, &mut ctx);
        ciphertext_vec.push(ciphertext);
    });
    
    //comparison matrix
    let mut comparison_matrix :Vec<Vec<u64>> = vec![vec![0; ctx.full_message_modulus()]; ctx.full_message_modulus()];
    for i in 0..ctx.full_message_modulus() {
        for j in 0..ctx.full_message_modulus() {
            if i <= j {
                comparison_matrix[i][j] = 1;
            } else {
                comparison_matrix[i][j] = 0;
            }
        }
    }

    // convert comparison matrix to lut
    let mut comparison_matrix_lut :Vec<LUT> = Vec::new();
    for i in 0..comparison_matrix.len(){
        comparison_matrix_lut.push(LUT::from_vec(&comparison_matrix[i], private_key, &mut ctx));
    }

    // initialize min to the first element, and argmin to its index
    let mut min = ciphertext_vec[0].clone();
    let mut argmin = public_key.allocate_and_trivially_encrypt_lwe(0u64, &ctx);

    let start = std::time::Instant::now();
    
    // loop and search for min and armgin
    for i in 1..ciphertext_vec.len() {
        let e = ciphertext_vec[i].clone();
        let b = public_key.blind_matrix_access(&comparison_matrix_lut, &min, &e, &mut ctx);

        let enc_i = public_key.allocate_and_trivially_encrypt_lwe(i as u64, &ctx);
        let lut_indices = LUT::from_vec_of_lwe(&[enc_i, argmin.clone()], public_key, &ctx);
        let lut_messages = LUT::from_vec_of_lwe(&[e, min], public_key, &ctx);

        argmin = public_key.blind_array_access(&b, &lut_indices, &ctx);
        min = public_key.blind_array_access(&b, &lut_messages, &ctx);

    }

    private_key.debug_lwe("Found argmin", &argmin, &ctx);

    let end = std::time::Instant::now();
    let elapsed = end.duration_since(start);
    println!("Time elapsed: {:?}", elapsed);


}

