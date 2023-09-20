use std::time::Duration;
use std::time::Instant;
use std::vec;

use rayon::prelude::*;

use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

use revolut::*;

// #[path = "./headers.rs"] mod headers;
// use self::headers::PrivateKey;
// use self::headers::PublicKey;
// use self::headers::Context;
// use self::headers::LUT;



pub fn blind_retrieve(){

    // let mut total_time = Duration::default();

    // for _ in 0..100{


    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


   
    let mut original_array = vec![2,4,9,6];
    original_array.resize(ctx.full_message_modulus(),0);

    println!("Original array : {:?} ",original_array );
    let index_retrieve_u64 = 2u64;


    let mut lut_original_array = LUT::from_vec(&original_array, &private_key, &mut ctx);
    let index_retrieve = private_key.allocate_and_encrypt_lwe(index_retrieve_u64, &mut ctx);
    let mut big_lwe = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    let mut lwe_retrieve = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());


    let mut ct_16 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    trivially_encrypt_lwe_ciphertext(&mut ct_16, Plaintext(ctx.full_message_modulus() as u64));

    let start_retrieve = Instant::now();

    // Delete the retrieved element from the lut
    
    let start_get = Instant::now();
        // get the element wanted
    blind_rotate_assign(&index_retrieve, &mut lut_original_array.0, &public_key.fourier_bsk);
    extract_lwe_sample_from_glwe_ciphertext(&lut_original_array.0, &mut big_lwe, MonomialDegree(0));
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &big_lwe , &mut lwe_retrieve);

    let duration_get = start_get.elapsed();
    println!("Time getting the element : {:?}", duration_get);




    let start_deletion = Instant::now();

        // delete it from the lut
    let lut_retrieve = LUT::from_lwe(&lwe_retrieve, public_key, &ctx);
    let mut lut_sum = LUT(public_key.glwe_sum(&lut_original_array.0, &lut_retrieve.0 ));
        // rerotate the lut
    let neg_index_retrieve = public_key.neg_lwe(&index_retrieve, &ctx);
    blind_rotate_assign(&neg_index_retrieve, &mut lut_sum.0, &public_key.fourier_bsk);

    let duration_deletion = start_deletion.elapsed();
    println!("Time deleting the element : {:?}", duration_deletion);




        
    let start_depack = Instant::now();
    // One LUT to many LUT
    let mut many_lut = lut_sum.to_many_lut(public_key, &ctx);

    let duration_depack = start_depack.elapsed();
    println!("Time depacking the intermediate lut : {:?}", duration_depack);


    let start_update_index = Instant::now();

    // Updating the index
    let mut new_index : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    for original_index in 0..many_lut.len(){

        let ct_cp = leq_scalar(&index_retrieve, original_index as u64, public_key, &ctx);
        // private_key.debug_lwe("ct_cp = ", &ct_cp, &ctx);
        let ct_original_index = public_key.allocate_and_trivially_encrypt_lwe(original_index as u64, &mut ctx);
        let mut ct_new_index = LweCiphertext::new(0_u64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
        // println!("original_index {}",original_index);
        lwe_ciphertext_sub(&mut ct_new_index, &ct_original_index, &ct_cp); // new index = original_index - ct_cp
        // private_key.debug_lwe("ct_new_index", &ct_new_index, &ctx);
        new_index.push(ct_new_index);
        
    }

    let duration_update_index = start_update_index.elapsed();
    println!("Time updating the index {:?}", duration_update_index);



    
    // Multi Blind Rotate

    let start_multi_br = Instant::now();
    for (lut,index) in many_lut.iter_mut().zip(new_index.iter()){
        let mut rotation = LweCiphertext::new(0_64,ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
        lwe_ciphertext_sub(&mut rotation, &ct_16, index); // rotation = 16 - index = - index
        blind_rotate_assign(&rotation, &mut lut.0, &public_key.fourier_bsk);
    }

    let duration_multi_br = start_multi_br.elapsed();
    println!("Time multi BR {:?}", duration_multi_br);
    

    // Sum all the rotated glwe to get the final glwe retrieved

    let start_glwe_sum = Instant::now();

    let mut result = many_lut[0].0.clone();
    for i in 1..many_lut.len(){
        result = public_key.glwe_sum(&result,&many_lut[i].0);
    }

    let new_lut = LUT(result);



    // let end_retrieve = Instant::now();
    // let time_retrieve = end_retrieve - start_retrieve;


    // total_time = total_time + time_retrieve;

    // }
    // let average_time = total_time / 100 as u32;


    // println!("Temps moyen d'exécution retrieve : {:?}", average_time);


    // // verification by extracting lwe 
    // fun_name(ctx, result, public_key, ct_16, private_key);


    new_lut.print_in_array_format(&private_key, &ctx);

    


    // println!("Time retrieve : {:?}",duration_retrieve);


}

fn fun_name(mut ctx: Context, result: GlweCiphertext<Vec<u64>>, public_key: &PublicKey, ct_16: LweCiphertext<Vec<u64>>, private_key: PrivateKey) {
    let half_box_size = ctx.box_size() / 2;

    let mut result_insert: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    result_insert.par_extend(
    (0..ctx.full_message_modulus())
        .into_par_iter()
        .map(|i| {
            let mut lwe_sample = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
            extract_lwe_sample_from_glwe_ciphertext(
                &result,
                &mut lwe_sample,
                MonomialDegree((i * ctx.box_size() + half_box_size) as usize),
            );
            let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_sample, &mut switched);

            // switched

            // the result will be modulo 32
            let mut output = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
            lwe_ciphertext_sub(&mut output,&ct_16 , &switched);
            output
        }),
    );


    let mut result_retrieve_u64 : Vec<u64> = Vec::new();
    for lwe in result_insert{
        let pt = private_key.decrypt_lwe(&lwe, &mut ctx);
        result_retrieve_u64.push(pt);
    }
    println!("Final array : {:?} ",result_retrieve_u64 );
}

fn one_lut_to_many_lut(lut: LUT, public_key: &PublicKey, ctx: &Context) -> Vec<LUT> {
    let many_lwe = lut.to_many_lwe(public_key, ctx);

    // Many-Lwe to Many-Glwe
    let mut many_glwe : Vec<LUT> = Vec::new();
    for lwe in many_lwe{
        let mut glwe = GlweCiphertext::new(0_u64,ctx.glwe_dimension().to_glwe_size(),ctx.polynomial_size(), ctx.ciphertext_modulus());
        let redundancy_lwe = one_lwe_to_lwe_ciphertext_list(lwe, ctx);
        private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
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
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut res_cmp, &mut switched);

    switched
}





#[cfg(test)]
mod test{

    use super::*;

    #[test]
    fn test_blind_retrieve(){

            blind_retrieve();
        
    }
}