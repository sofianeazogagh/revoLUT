
use std::time::Instant;
use std::vec;


use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

// #[path = "./headers.rs"] mod headers;
// use self::headers::PrivateKey;
// use self::headers::PublicKey;
// use self::headers::Context;
// use self::headers::LUT;



use revolut::*;




pub fn blind_insertion(){

    // let mut total_time = Duration::default();

    // for _ in 0..100{

    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


   
    let mut original_array = vec![2,4,6,2,4,9];
    original_array.resize(ctx.full_message_modulus(),0);

    println!("Original array : {:?} ",original_array );
    let insertion_u64 = 12u64;
    let index_insertion_u64 = 5u64;


    let lut_original_array = LUT::from_vec(&original_array, &private_key, &mut ctx);
    let lwe_insertion = private_key.allocate_and_encrypt_lwe(insertion_u64, &mut ctx);
    let index_insertion = private_key.allocate_and_encrypt_lwe(index_insertion_u64, &mut ctx);


    let start_insertion = Instant::now();



    // One LUT to many LUT
    let mut many_lut = lut_original_array.to_many_lut(public_key, &ctx);

    let lut_insertion = LUT::from_lwe(&lwe_insertion, public_key, &ctx);


    //Updating the index

    let mut new_index : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    for original_index in 0..many_lut.len(){

        let mut ct_cp = leq_scalar(&index_insertion, original_index as u64, public_key, &ctx);
        let ct_original_index = public_key.allocate_and_trivially_encrypt_lwe(original_index as u64, &mut ctx);
        lwe_ciphertext_add_assign(&mut ct_cp, &ct_original_index); // new index = ct_cp + original_index 
        new_index.push(ct_cp);
        
    }
    new_index[ctx.full_message_modulus()-1] = index_insertion;
    many_lut[ctx.full_message_modulus()-1] = lut_insertion;



    // Multi Blind Rotate
    let mut ct_16 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    trivially_encrypt_lwe_ciphertext(&mut ct_16, Plaintext(ctx.full_message_modulus() as u64)); // chiffré trival de 32 : (0,..,0,32)
    for (lut,index) in many_lut.iter_mut().zip(new_index.iter()){
        let mut rotation = LweCiphertext::new(0_64,ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
        lwe_ciphertext_sub(&mut rotation, &ct_16, index); // rotation = 16 - index = - index
        blind_rotate_assign(&rotation, &mut lut.0, &public_key.fourier_bsk);
    }


    // Sum all the rotated glwe to get the final glwe permuted
    let mut result = many_lut[0].0.clone();
    for i in 1..many_lut.len(){
        result = public_key.glwe_sum(&result,&many_lut[i].0);
    }

    // private_key.debug_glwe("after Sum", &result, &ctx);


    


    let duration_insertion = start_insertion.elapsed();

    let result_in_lut = LUT(result);
    result_in_lut.print_in_glwe_format(&private_key, &ctx);

    // let end_insert = Instant::now();
    // let time_insert = end_insert - start_insertion;
    // total_time = total_time + time_insert;
    // }
    // let average_time = total_time / 100 as u32;
    // println!("Temps moyen d'exécution insert : {:?}", average_time);


    // // verification by extracting lwe 
    // let half_box_size = ctx.box_size() / 2;
    // let mut ct_16 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
    // trivially_encrypt_lwe_ciphertext(&mut ct_16, Plaintext(ctx.full_message_modulus() as u64));

    // let mut result_insert: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    // result_insert.par_extend(
    // (0..ctx.full_message_modulus())
    //     .into_par_iter()
    //     .map(|i| {
    //         let mut lwe_sample = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size());
    //         extract_lwe_sample_from_glwe_ciphertext(
    //             &result,
    //             &mut lwe_sample,
    //             MonomialDegree((i * ctx.box_size() + half_box_size) as usize),
    //         );
    //         let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
    //         par_keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_sample, &mut switched);

    //         // switched

    //         // the result will be modulo 32
    //         let mut output = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
    //         lwe_ciphertext_sub(&mut output,&ct_16 , &switched);
    //         output
    //     }),
    // );


    // let mut result_insert_u64 : Vec<u64> = Vec::new();
    // for lwe in result_insert{
    //     let pt = private_key.decrypt_lwe(&lwe, &mut ctx);
    //     result_insert_u64.push(pt);
    // }
    // println!("Inserted array : {:?} ",result_insert_u64 );


    // let mut ground_truth = original_array;
    // ground_truth.insert(index_insertion_u64 as usize, insertion_u64);
    // ground_truth.resize(ctx.full_message_modulus(), 0);
    // assert_eq!(result_insert_u64,ground_truth);
    // println!("gt = {:?}",ground_truth);



    println!("Time insertion : {:?}",duration_insertion);


}

fn one_lut_to_many_lut(lut: LUT, public_key: &PublicKey, ctx: &Context) -> Vec<LUT> {
    let many_lwe = lut.to_many_lwe(public_key, ctx);

    // Many-Lwe to Many-Glwe
    let mut many_glwe : Vec<LUT> = Vec::new();
    for lwe in many_lwe{
        let mut glwe = GlweCiphertext::new(0_u64,ctx.glwe_dimension().to_glwe_size(),ctx.polynomial_size(), ctx.ciphertext_modulus());
        let redundancy_lwe = one_lwe_to_lwe_ciphertext_list(lwe, ctx);
        par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &redundancy_lwe,
            &mut glwe,
           );
        many_glwe.push(LUT(glwe));
    }
    many_glwe
}








fn one_lwe_to_lwe_ciphertext_list(
    input_lwe: LweCiphertext<Vec<u64>>,
    ctx : &Context
) 
-> LweCiphertextList<Vec<u64>> 
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.

    let redundant_lwe = vec![input_lwe.into_container();ctx.box_size()].concat();
    let lwe_ciphertext_list =  LweCiphertextList::from_container(
        redundant_lwe,
        ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    

    lwe_ciphertext_list
}






pub fn leq_scalar(
    ct_input: &LweCiphertext<Vec<u64>>,
    scalar : u64,
    public_key : &PublicKey,
    ctx : &Context
) -> LweCiphertext<Vec<u64>> 
{

    let cmp_scalar_accumulator = LUT::from_function(|x| (x <= scalar as u64) as u64, ctx);
    let mut res_cmp = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    programmable_bootstrap_lwe_ciphertext(
        &ct_input,
        &mut res_cmp,
        &cmp_scalar_accumulator.0,
        &public_key.fourier_bsk,
    );
    let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    par_keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut res_cmp, &mut switched);

    switched
}





#[cfg(test)]
mod test{

    use super::*;

    #[test]
    fn test_blind_insertion(){

            blind_insertion();
        
    }
}