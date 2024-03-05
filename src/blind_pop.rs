
use std::time::Instant;
use std::vec;



use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

// #[path = "./headers.rs"] mod headers;
// use self::headers::PrivateKey;
// use self::headers::PublicKey;
// use self::headers::Context;
// use self::headers::LUT;
// use self::headers::LUTStack;


use revolut::*;


pub fn blind_pop(){

    // let mut total_time = Duration::default();

    // for _ in 0..100{



    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


   
    let original_array = vec![2,4,6,9];
    // println!("Original array : {:?} ",original_array );

    

    let mut lut_original = LUTStack::from_vec(&original_array, &private_key, &mut ctx);


    let mut ct_16 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    trivially_encrypt_lwe_ciphertext(&mut ct_16, Plaintext(ctx.full_message_modulus() as u64 * ctx.delta()));

    let lwe_one = public_key.allocate_and_trivially_encrypt_lwe(1_u64, &ctx);

    let start_pop = Instant::now();

    

    let mut lwe_pop = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    let mut lwe_pop_not_switched = LweCiphertext::new(0, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    let stack_len = lut_original.number_of_elements;

    let mut rotation = LweCiphertext::new(0_64,ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());

    lwe_ciphertext_sub(&mut rotation, &stack_len, &lwe_one); // rotation = stack_len - 1
    blind_rotate_assign(&rotation, &mut lut_original.lut.0, &public_key.fourier_bsk);

    extract_lwe_sample_from_glwe_ciphertext(&lut_original.lut.0, &mut lwe_pop_not_switched, MonomialDegree(0));
    par_keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &lwe_pop_not_switched, &mut lwe_pop);


    let lut_used_to_delete = LUT::from_lwe(&lwe_pop, &public_key, &ctx);

    // Sum the rotated glwe with the lut poped and rotate it
    let mut result = LUT(public_key.glwe_sum(&lut_original.lut.0, &lut_used_to_delete.0 ));
    public_key.wrapping_neg_lwe(&mut rotation);
    blind_rotate_assign(&rotation, &mut result.0, &public_key.fourier_bsk);

    
    // TODO : mettre a jour number of element et nouvelle lut dans lut_original

    let lwe_one = public_key.allocate_and_trivially_encrypt_lwe(1_u64, &ctx);
    let mut new_number_of_element = LweCiphertext::new(0_u64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    lwe_ciphertext_sub(&mut new_number_of_element, &stack_len, &lwe_one);

    let _lut_pop = LUTStack{
        lut : result,
        number_of_elements : new_number_of_element
    };


    let duration_pop = start_pop.elapsed();

    // let end_pop = Instant::now();
    // let time_pop = end_pop - start_pop;


    // total_time = total_time + time_pop;

    // }
    // let average_time = total_time / 100 as u32;


    // println!("Temps moyen d'exécution blind_push : {:?}", average_time);


    // // verification by extracting lwe 
    // let half_box_size = ctx.box_size() / 2;

    // let mut result_pop: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    // result_pop.par_extend(
    // (0..ctx.full_message_modulus())
    //     .into_par_iter()
    //     .map(|i| {
    //         let mut lwe_sample = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size());
    //         extract_lwe_sample_from_glwe_ciphertext(
    //             &lut_pop.lut.0,
    //             &mut lwe_sample,
    //             MonomialDegree((i*ctx.box_size() + half_box_size - 1) as usize),
    //         );
    //         // key switching
    //         let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
    //         par_keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_sample, &mut switched);
    //         switched
    //     }),
    // );


    // let mut result_pop_u64 : Vec<u64> = Vec::new();
    // for lwe in result_pop{
    //     let pt = private_key.decrypt_lwe(&lwe, &mut ctx);
    //     result_pop_u64.push(pt);
    // }
    // println!("Array pop : {:?} ",result_pop_u64 );

    println!("Time pop : {:?}",duration_pop);


}






fn one_lut_to_many_lut(lut: LUT, public_key: &PublicKey, ctx: &Context) -> Vec<LUT> {
    let many_lwe = lut.to_many_lwe(public_key, ctx);

    // Many-Lwe to Many-Glwe
    let mut many_glwe : Vec<LUT> = Vec::new();
    for lwe in many_lwe{
        let mut glwe = GlweCiphertext::new(0_u64,ctx.glwe_dimension().to_glwe_size(),ctx.polynomial_size(), ctx.ciphertext_modulus());
        let redundancy_lwe = one_lwe_to_lwe_ciphertext_list(lwe, ctx);
        par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &mut glwe,
            &redundancy_lwe);
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
    fn test_blind_pop(){

            blind_pop();
        
    }
}