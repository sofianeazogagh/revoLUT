
use std::time::Duration;
use std::time::Instant;
use rayon::prelude::*;

use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;

#[path = "./headers.rs"] mod headers;
use self::headers::PrivateKey;
use self::headers::PublicKey;
use self::headers::Context;
use self::headers::LUT;





pub fn blind_array_access() {


    // let mut total_time = Duration::default();

    // for _ in 0..100{


    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    // Our input message
    let input = 3;

    // let line = 1u64;
    // let column = 2;


    let lwe_input = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
    

    // let array = vec![8,9,10,11,8,9,10,11];
    let array = vec![8,9,10,11];


    let lut = LUT::from_vec(&array, &private_key, &mut ctx);

    let start_bacc = Instant::now();
    let mut ct_res = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
    programmable_bootstrap_lwe_ciphertext(&lwe_input, &mut ct_res, &lut.0, &public_key.fourier_bsk,);
    let duration_bacc = start_bacc.elapsed();
    println!("Time BACC2D = {:?}",duration_bacc);


    // let end_bacc = Instant::now();
    // let time_bacc = end_bacc - start_bacc;


    // total_time = total_time + time_bacc;

    // }
    // let average_time = total_time / 100 as u32;


    // println!("Temps moyen d'exécution bacc2d : {:?}", average_time);




    // let result = private_key.decrypt_lwe_big_key(&ct_res, &mut ctx);

    // println!("Checking result...");
    // println!("BACC input {input} got {result}");


}


